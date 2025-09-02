#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <termios.h>

#include <QCoreApplication>
#include <QDebug>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QStringList>
#include <QTextStream>
#include <QThread>
#include <QtConcurrent>

#define HELP_BASE " [-c CONFIG] [-a] [-y] [-n] [-e]\n"
#define HELP_COMMANDS                                                                                                          \
    "  help    (self explanable) \n"                                                                                           \
    "  list    (default command) \n"                                                                                           \
    "  hosts   (basic hosts info) \n"                                                                                          \
    "  start   CONTAINER[s] | VM[s]\n"                                                                                         \
    "  stop    CONTAINER[s] | VM[s]\n"                                                                                         \
    "  kill    CONTAINER[s] | VM[s]\n"                                                                                         \
    "  restart CONTAINER[s] | VM[s]\n"                                                                                         \
    "  enable  CONTAINER[s] | VM[s]\n"                                                                                         \
    "  disable CONTAINER[s] | VM[s]\n"                                                                                         \
    "  remove  CONTAINER[s] | VM[s]\n"                                                                                         \
    "  rename  CONTAINER    | VM    NEW_NAME\n"                                                                                \
    "  spread  CONTAINER[s] | VM[s]             (create copy named CONTAINER.backup on all hosts with same arch in cluster)\n" \
    "  backup  CONTAINER[s] | VM[s] MACHINE:DIR (backup container or VM to dst DIR using rsync)\n"                             \
    "  move    CONTAINER    | VM    TARGET      (move container to TARGET and rename old container as CONTAINER.backup)\n"     \
    "  clone   CONTAINER            CLONE_NAME  (clone container as new)\n"                                                    \
    "  exec    CONTAINER[s]         cmd...parms (run command in container)\n"                                                  \
    "  shell   (connect to hosts and wait for commands)\n"

#define COLOR_GRN "\033[0;32m"
#define COLOR_RED "\033[0;31m"
#define COLOR_BLUE "\033[0;34m"
#define COLOR_CYAN "\033[0;36m"
#define COLOR_PURPLE "\033[0;35m"
#define COLOR_BROWN "\033[0;33m"
#define COLOR_OFF "\033[0m"
#define BACKGROUND_BLUE "\033[48;5;17m"

#define RSYNC_VANISHED 24

const QByteArray defaultConfig =
    "{ \"sshKeyPath\" : \"/root/.ssh/id_ecdsa\", \"hosts\" : [ {\"virsh\" : true, \"hostname\" : \"localhost\", \"address\" : \"127.0.0.1\"} ] }";

typedef struct {
    qreal total;
    qreal used;
} df_t;

typedef struct {
    ssh_session session;
    ssh_key key;
    QString arch;
    bool waiting;
    QString addr;
    QString name;
    bool virsh;
    QStringList bridges;
    bool connected;
    QList<df_t> space;
} ssh_t;

typedef struct {
    QString name;
    QString type;
    QString addresses;
    QString status;
    QString os;
    QString containerPath;
    QStringList vmImageList;
    QStringList vmBaseImageList;
    QStringList interfaces;
    ssh_t* ssh;
} machine_t;

QMap<QString, QString> colorTable = {{"green", COLOR_GRN}, {"red", COLOR_RED},       {"blue", COLOR_BLUE},
                                     {"cyan", COLOR_CYAN}, {"purple", COLOR_PURPLE}, {"brown", COLOR_BROWN}};
QMap<QString, QString> colorAssociation;

QList<ssh_t*> sshConnList;
QList<machine_t*> machineList;
QString sshKeyPath;
bool showBackups = false;
bool showextended = false;
bool dontAsk = false;
bool allNo = false;
static int lastExitCode = 0;

QByteArray runSsh(ssh_t* ssh, QStringList params, bool interactive = false, QByteArray data = QByteArray());

QFile& qStdIn() {
    static QFile in;
    if (!in.isOpen()) {
        in.open(stdin, QIODevice::ReadOnly | QIODevice::Unbuffered);
    }
    return in;
}

QTextStream& qStdOut() {
    static QTextStream ts(stdout);
    return ts;
}

QTextStream& qStdErr() {
    static QTextStream ts(stderr);
    return ts;
}

bool sshConnect(const QJsonArray& hosts) {
    int waiting = 0;
    for (const QJsonValue& v : hosts) {
        ssh_t* ssh = new ssh_t();
        int rc;
        ssh->addr = v.toObject().value("address").toString();
        ssh->name = v.toObject().value("hostname").toString();
        ssh->virsh = v.toObject().value("virsh").toBool(true);
        ssh->session = ssh_new();
        ssh->connected = false;
        ssh_options_set(ssh->session, SSH_OPTIONS_HOST, ssh->addr.toUtf8().constData());
        ssh_options_set(ssh->session, SSH_OPTIONS_USER, "root");
        ssh_options_set(ssh->session, SSH_OPTIONS_LOG_VERBOSITY_STR, "SSH_LOG_NOLOG");
        ssh_set_blocking(ssh->session, 0);
        rc = ssh_connect(ssh->session);
        if (rc != SSH_AGAIN) {
            qInfo() << "Unable to connect to:" << ssh->name;
            return (false);
        }
        ssh->waiting = true;
        sshConnList << ssh;
    }

    waiting = sshConnList.length();
    QElapsedTimer timer;
    timer.start();
    while (waiting) {
        bool willBreak = false;
        if (timer.elapsed() > (1000 * 5)) {
            willBreak = true;
        }
        for (auto ssh : sshConnList) {
            if (!ssh->waiting) {
                continue;
            }
            int rc = ssh_connect(ssh->session);
            if (rc == SSH_AGAIN) {
                // ook, wait for next
            } else if (rc == SSH_OK) {
                ssh->waiting = false;
                ssh->connected = true;
                waiting--;
            } else {
                qInfo() << "Unable to connect to:" << ssh->name;
            }
            if (timer.elapsed() > (1000 * 5)) {
                qInfo() << "Connection timeout" << ssh->name;
            }
        }
        if (willBreak) {
            break;
        }
        QThread::msleep(4);
    }

    for (auto ssh : sshConnList) {
        int rc;
        if (!ssh->connected) {
            continue;
        }
        enum ssh_known_hosts_e is_known;
        is_known = ssh_session_is_known_server(ssh->session);
        if (is_known != SSH_KNOWN_HOSTS_OK) {
            qInfo() << "Host with unknown or invalid ID:" << ssh->addr << ssh->name;
            sshConnList.clear();
            return (false);
        }
        ssh->waiting = true;
        rc = ssh_pki_import_privkey_file(sshKeyPath.toUtf8().constData(), nullptr, nullptr, nullptr, &ssh->key);
        if (rc == SSH_OK) {
            rc = ssh_userauth_publickey(ssh->session, "root", ssh->key);
        } else {
            qInfo() << "Unable to load key";
            sshConnList.clear();
            return (false);
        }
        if (rc != SSH_AUTH_AGAIN) {
            qInfo() << "Auth failed too early:" << ssh->name << rc;
            ;
            sshConnList.clear();
            return (false);
        }
    }

    waiting = sshConnList.length();
    while (waiting) {
        for (auto ssh : sshConnList) {
            if (!ssh->waiting) {
                continue;
            }
            if (!ssh->connected) {
                waiting--;
                ssh->waiting = false;
                continue;
            }
            int rc = ssh_userauth_publickey(ssh->session, "root", ssh->key);
            if (rc == SSH_AUTH_AGAIN) {
                // ook, wait for next
            } else if (rc == SSH_AUTH_SUCCESS) {
                ssh->waiting = false;
                ssh_set_blocking(ssh->session, 1);
                waiting--;
            } else {
                qInfo() << "Unable to auth to:" << ssh->name;
                sshConnList.clear();
                return (false);
            }
        }
        QThread::msleep(4);
    }

    QList<ssh_t*> tmp;
    for (auto ssh : sshConnList) {
        if (ssh->connected) {
            QString arch = QString::fromUtf8(runSsh(ssh, {"arch"})).remove("\n");
            if (lastExitCode == 0) {
                ssh->arch = arch;
            } else {
                ssh->arch = "UNKNOWN";
            }
            QJsonArray interfaces = QJsonDocument::fromJson(runSsh(ssh, {"ip", "-j", "link", "show", "type", "bridge"})).array();
            if (lastExitCode == 0) {
                for (const QJsonValue& v : interfaces) {
                    if (!v.isObject()) {
                        qInfo() << "Invalid bridge object";
                        continue;
                    }
                    ssh->bridges << v.toObject().value("ifname").toString();
                }
                ssh->bridges.sort();
            }
            QStringList space =
                QString::fromUtf8(runSsh(ssh, {"df", "/var/lib/libvirt/images/", "/var/lib/machines/", "/var/lib/container/"})).split("\n", Qt::SkipEmptyParts);
            for (const QString& s : space) {
                if (s.startsWith("File") || s.startsWith("df")) {
                    continue;
                }
                df_t df;
                QStringList values = s.split(" ", Qt::SkipEmptyParts);
                if (values.count() < 5) {
                    continue;
                }
                df.total = values[1].toDouble() / (1024 * 1024);
                df.used = values[2].toDouble() / (1024 * 1024);
                ssh->space << df;
            }
            tmp << ssh;
        } else {
            qInfo() << ssh->name << "ERR";
        }
    }
    sshConnList = tmp;
    return (true);
}

QByteArray runSsh(ssh_t* ssh, QStringList params, bool interactive, QByteArray data) {
    QByteArray ret;
    ssh_channel channel;
    bool dataToWrite = true;
    channel = ssh_channel_new(ssh->session);
    if (channel == nullptr) {
        qInfo() << "SSH channel failed:" << ssh->name;
        lastExitCode = -1;
        return (ret);
    }
    int rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        lastExitCode = -1;
        return (ret);
    }
    struct termios termios_saved, termios_raw;
    if (interactive) {
        int lines = qEnvironmentVariableIntValue("LINES");
        int columns = qEnvironmentVariableIntValue("COLUMNS");
        rc = ssh_channel_request_pty(channel);
        if (rc != SSH_OK) {
            lastExitCode = -1;
            return (ret);
        }
        rc = ssh_channel_change_pty_size(channel, columns, lines);
        if (rc != SSH_OK) {
            lastExitCode = -1;
            return (ret);
        }
        tcgetattr(0, &termios_saved);
        termios_raw = termios_saved;
        cfmakeraw(&termios_raw);
        tcsetattr(0, 0, &termios_raw);
    }
    ssh_channel_request_exec(channel, params.join(" ").toUtf8().constData());
    do {
        char buf[1024];
        int len = ssh_channel_read_timeout(channel, buf, 1024, 0, 10);
        if (len) {
            if (interactive) {
                // qInfo() << "read:" << buf;
                qStdOut() << QByteArray(buf, len);
                qStdOut().flush();
            } else {
                ret += QByteArray(buf, len);
            }
        }
        len = ssh_channel_read_timeout(channel, buf, 1024, 1, 10);
        if (len) {
            if (interactive) {
                qStdErr() << QByteArray(buf, len);
                qStdErr().flush();
            } else {
                ret += QByteArray(buf, len);
            }
        }
        if (interactive) {
            int avail = 0;
            if (ioctl(0, FIONREAD, &avail) == 0 && avail > 0) {
                unsigned char buf[avail];
                size_t r = read(0, buf, avail);
                ssh_channel_write(channel, buf, r);
            }
        }
        if (data.length() && dataToWrite) {
            ssh_channel_write(channel, data.constData(), data.length());
            ssh_channel_send_eof(channel);
            dataToWrite = false;
        }
        QThread::msleep(4);
    } while (!ssh_channel_is_eof(channel));
    if (interactive) {
        tcsetattr(0, 0, &termios_saved);
    }
    ssh_channel_send_eof(channel);
    lastExitCode = ssh_channel_get_exit_status(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return (ret);
}

bool runSshInteractive(ssh_t* ssh, const QStringList& params) {
    ssh_channel channel;
    channel = ssh_channel_new(ssh->session);
    if (channel == nullptr) {
        qInfo() << "SSH channel failed:" << ssh->name;
        lastExitCode = -1;
        return (false);
    }
    int rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        lastExitCode = -1;
        return (false);
    }
    ssh_channel_request_exec(channel, params.join(" ").toUtf8().constData());
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        lastExitCode = -1;
        return (false);
    }
    char buf[1024];
    QString out;
    do {
        int len = ssh_channel_read_timeout(channel, buf, 1024, 0, 50);
        if (len) {
            out = QString::fromUtf8(buf, len);
            if (!out.startsWith("skipping")) {
                qStdOut() << out;
                qStdOut().flush();
            }
        }
        len = ssh_channel_read_timeout(channel, buf, 1024, 1, 50);
        if (len) {
            out = QString::fromUtf8(buf, len);
            if (!out.startsWith("skipping")) {
                qStdErr() << out;
                qStdErr().flush();
            }
        }
    } while (!ssh_channel_is_eof(channel));
    ssh_channel_send_eof(channel);
    lastExitCode = ssh_channel_get_exit_status(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return (true);
}

QList<machine_t*> getMachineListFromHost(ssh_t* ssh) {
    QList<machine_t*> ret;
    QStringList containers;
    QJsonArray images = QJsonDocument::fromJson(runSsh(ssh, {"machinectl", "-o", "json", "list-images"})).array();
    foreach (const QJsonValue& vv, images) {
        QJsonObject oo = vv.toObject();
        if (oo.value("type") == "directory" && oo.contains("name")) {
            if (oo.value("name").toString().contains(" ")) {
                qInfo() << "Invalid offline CONTAINER name with spaces" << oo.value("name").toString();
                continue;
            }
            containers << oo.value("name").toString();
        }
    }
    if (ssh->virsh) {
        QStringList vms = QString::fromUtf8(runSsh(ssh, {"virsh", "list", "--all"})).split("\n", Qt::SkipEmptyParts);
        if (vms.length() > 2) {
            vms.takeFirst();
            vms.takeFirst();
            foreach (const QString& ss, vms) {
                QStringList spl = ss.split(" ", Qt::SkipEmptyParts);
                if (spl.length() > 1) {
                    if (spl[1].contains(" ")) {
                        qInfo() << "Invalid VM name with spaces:" << spl[1];
                        continue;
                    }
                    QString online = ss.contains("running") ? "ONLINE" : "OFFLINE";
                    machine_t* m = new machine_t();
                    m->ssh = ssh;
                    m->name = spl[1];
                    m->type = "vm";
                    m->status = online;
                    // get blkdev info
                    QStringList blockDevices = QString::fromUtf8(runSsh(ssh, {"virsh", "domblklist", m->name})).split("\n", Qt::SkipEmptyParts);
                    if (blockDevices.length() > 2) {
                        blockDevices.removeFirst();
                        blockDevices.removeFirst();
                        for (const QString& line : blockDevices) {
                            QStringList lineSplit = line.split(" ", Qt::SkipEmptyParts);
                            if (lineSplit.length() > 1) {
                                QString blkDev = lineSplit.at(1);
                                if (blkDev == "-") {
                                    continue;
                                }
                                QJsonArray backingList =
                                    QJsonDocument::fromJson(runSsh(ssh, {"qemu-img", "info", "--output", "json", "--backing-chain", "--force-share", blkDev}))
                                        .array();
                                for (const QJsonValue& v : backingList) {
                                    m->vmImageList << v.toObject().value("filename").toString();
                                }
                                m->vmBaseImageList << m->vmImageList.last();
                            }
                        }
                    }
                    QStringList ifList = QString::fromUtf8(runSsh(ssh, {"virsh", "domiflist", m->name})).split("\n", Qt::SkipEmptyParts);
                    if (ifList.length() > 2) {
                        ifList.takeFirst();
                        ifList.takeFirst();
                        for (const QString& l : ifList) {
                            QStringList line = l.split(" ", Qt::SkipEmptyParts);
                            if (line.length() > 2) {
                                m->interfaces << line[2];
                            }
                        }
                    }
                    if (online == "ONLINE") {
                        QJsonObject vmInfo =
                            QJsonDocument::fromJson(runSsh(ssh, {"virsh", "qemu-agent-command", m->name, "'{\"execute\":\"guest-get-osinfo\"}'"})).object();
                        if (vmInfo.contains("return")) {
                            vmInfo = vmInfo.value("return").toObject();
                            if (vmInfo.contains("name")) {
                                m->os = vmInfo.value("name").toString();
                            }
                            if (vmInfo.contains("version")) {
                                QString ver = vmInfo.value("version").toString();
                                if (ver.startsWith(m->os)) {
                                    m->os = ver;
                                } else {
                                    m->os += " " + ver;
                                }
                            }
                            m->os = m->os.remove("Microsoft ");
                            if (m->os.contains("(")) {
                                m->os = m->os.split("(", Qt::SkipEmptyParts).first();
                            }
                        }
                        QJsonObject nicInfo =
                            QJsonDocument::fromJson(runSsh(ssh, {"virsh", "qemu-agent-command", m->name, "'{\"execute\":\"guest-network-get-interfaces\"}'"}))
                                .object();
                        if (nicInfo.contains("return")) {
                            QJsonArray nicList = nicInfo.value("return").toArray();
                            QStringList addrList;
                            foreach (const QJsonValue& v, nicList) {
                                if (!v.isObject()) {
                                    continue;
                                }
                                QJsonObject o = v.toObject();
                                if (o.contains("ip-addresses")) {
                                    foreach (const QJsonValue& ip, o.value("ip-addresses").toArray()) {
                                        QString addr = ip.toObject().value("ip-address").toString();
                                        if (addr == "127.0.0.1" || addr == "::1" || addr.startsWith("169.254.")) {
                                            continue;  // skip loppback
                                        }
                                        addrList << addr;
                                    }
                                }
                            }
                            addrList.sort(Qt::CaseInsensitive);
                            m->addresses = addrList.join("\n");
                        }
                    }
                    ret << m;
                }
            }
        }
    }
    QByteArray res = runSsh(ssh, {"machinectl", "-o", "json"});
    if (res.length()) {
        QJsonArray sshResult = QJsonDocument::fromJson(res).array();
        foreach (const QJsonValue& vv, sshResult) {
            if (!vv.isObject()) {
                qInfo() << "Invalid host status:" << vv;
                continue;
            }
            QJsonObject oo = vv.toObject();
            if (oo.value("machine").toString().contains(" ")) {
                qInfo() << "Invalid CONTAINER name with spaces:" << oo.value("machine").toString();
                continue;
            }
            QString machine = oo.value("machine").toString();
            if (machine.startsWith("qemu-")) {
                continue;
            }
            machine_t* m = new machine_t();
            m->ssh = ssh;
            m->name = oo.value("machine").toString();
            m->type = oo.value("class").toString();
            m->addresses = oo.value("addresses").toString();
            m->os = oo.value("os").toString() + " " + oo.value("version").toString();
            m->status = "ONLINE";
            QStringList imageInfo = QString::fromUtf8(runSsh(ssh, {"machinectl", "show-image", m->name})).split("\n", Qt::SkipEmptyParts);
            for (QString& s : imageInfo) {
                if (s.startsWith("Path=")) {
                    s = s.remove("Path=");
                    m->containerPath = s;
                    break;
                }
            }
            QStringList nspawnConfig = QString::fromUtf8(runSsh(ssh, {"cat", "/etc/systemd/nspawn/" + m->name + ".nspawn"})).split("\n", Qt::SkipEmptyParts);
            for (QString& s : nspawnConfig) {
                s.remove(" ");
                if (s.startsWith("Bridge=")) {
                    s.remove("Bridge=");
                    m->interfaces << s;
                } else if (s.startsWith("VirtualEthernetExtra=")) {
                    QStringList vee = s.split(":", Qt::SkipEmptyParts);
                    if (vee.count() == 2) {
                        m->interfaces << vee[1];
                    }
                }
            }
            if (m->containerPath.length() == 0) {
                qInfo() << "Container with no path?" << m->name << "on" << m->ssh->name;
            } else {
                ret << m;
            }
            containers.removeAll(oo.value("machine").toString());
        }
    }
    foreach (const QString& s, containers) {
        machine_t* m = new machine_t();
        m->ssh = ssh;
        m->name = s;
        m->type = "container";
        m->status = "OFFLINE";
        QStringList imageInfo = QString::fromUtf8(runSsh(ssh, {"machinectl", "show-image", m->name})).split("\n", Qt::SkipEmptyParts);
        for (QString& s : imageInfo) {
            if (s.startsWith("Path=")) {
                s = s.remove("Path=");
                m->containerPath = s;
                break;
            }
        }
        QStringList nspawnConfig = QString::fromUtf8(runSsh(ssh, {"cat", "/etc/systemd/nspawn/" + m->name + ".nspawn"})).split("\n", Qt::SkipEmptyParts);
        for (QString& s : nspawnConfig) {
            s.remove(" ");
            if (s.startsWith("Bridge=")) {
                s.remove("Bridge=");
                m->interfaces << s;
            } else if (s.startsWith("VirtualEthernetExtra=")) {
                QStringList vee = s.split(":", Qt::SkipEmptyParts);
                if (vee.count() == 2) {
                    m->interfaces << vee[1];
                }
            }
        }
        ret << m;
    }
    return (ret);
}

void getMachineList() {
    for (machine_t* m : machineList) {
        delete m;
    }
    machineList.clear();
    QList<QList<machine_t*>> tmpRes = QtConcurrent::blockingMapped(sshConnList, getMachineListFromHost);
    for (auto& l : tmpRes) {
        machineList << l;
    }
    QHash<QString, machine_t*> test;
    foreach (auto m, machineList) {
        QString n = m->name;
        if (test.contains(n) && !n.endsWith(".backup")) {
            qInfo() << "WARNING: Duplicate machine found";
            qInfo() << test[n]->name << test[n]->type << test[n]->ssh->name << test[n]->ssh->addr;
            qInfo() << m->name << m->type << m->ssh->name << m->ssh->addr;
        } else {
            test.insert(n, m);
        }
    }
}

ssh_t* findSsh(QString name) {
    for (auto ssh : sshConnList) {
        if (ssh->name == name) {
            return (ssh);
            break;
        }
    }
    return (nullptr);
}

machine_t* findMachine(QString name, ssh_t* ssh = nullptr) {
    machine_t* h = nullptr;
    foreach (auto m, machineList) {
        if (ssh && m->ssh != ssh) {
            continue;
        }
        if (m->name == name) {
            if (h != nullptr) {
                qInfo() << "Duplicate machine";
                qInfo() << m->name << "on" << m->ssh->name;
                if (!h->name.endsWith(".backup")) {
                    return (nullptr);
                }
            }
            h = m;
        }
    }
    return (h);
}

bool askYes(QString question) {
    if (allNo == true) {
        return (false);
    }
    if (dontAsk == false) {
        qStdOut() << question << " [Y/N]: ";
        qStdOut().flush();
        QString response = QString::fromUtf8(qStdIn().readLine(4));
        response.remove("\n");
        if (response != "Y") {
            return (false);
        }
    }
    return (true);
}

bool backupMachine(machine_t* m, ssh_t* targetSsh = nullptr, QString targetDir = "", bool vanishedOk = false) {
    bool ret = true;

    qStdOut() << "Backup from: " << m->ssh->name << ":" << m->name << "\n";
    qStdOut().flush();
    foreach (auto target, sshConnList) {
        bool skip = false;
        if (target->addr == m->ssh->addr && targetDir.length() == 0) {
            continue;
        }
        if (target->arch != m->ssh->arch && targetDir.length() == 0) {
            qInfo() << "Target arch:" << target->arch << "on" << target->name << "differs from" << m->ssh->arch << " ... skipping";
            if (targetSsh->name != nullptr) {
                return (false);
            }
            break;
        }
        if (targetSsh != nullptr && targetSsh->addr != target->addr) {
            continue;
        }
        QString dstDir;
        if (targetDir.length() == 0) {
            for (const QString intf : m->interfaces) {
                if (!target->bridges.contains(intf)) {
                    qInfo() << "Interface:" << intf << "missing on" << target->name << " ... skipping";
                    if (targetSsh != nullptr) {
                        return (false);
                    }
                    skip = true;
                    break;
                }
            }
            if (skip) {
                continue;
            }
            dstDir = m->containerPath + ".backup/";
        } else {
            if (m->type == "container") {
                dstDir = targetDir + "/" + m->name + "/root/";
            } else {
                dstDir = targetDir + "/" + m->name + "/images/";
            }

            if (!targetDir.startsWith("/")) {
                qInfo() << "Unable sync to relative path" << targetDir;
                return (false);
            }

            runSsh(m->ssh, {"ssh", target->addr, "test", "-d", "/"});
            if (lastExitCode != 0) {
                qInfo() << "Unable to connect from source:" << m->ssh->name << "to target:" << target->name;
                return (false);
            }

            runSsh(target, {"test", "-d", targetDir});
            if (lastExitCode != 0) {
                qInfo() << "Target dir missing" << targetDir;
                return (false);
            }

            runSsh(target, {"mkdir", "-p", dstDir});
            if (lastExitCode != 0) {
                qInfo() << "Unable to create dstDir" << dstDir;
                return (false);
            }
        }

        if (m->type == "container") {
            QStringList params = QStringList({"rsync", "-aAXpx", "-e", "\"ssh -T -o Compression=no -x\"", "--info=progress2", "--numeric-ids", "--no-devices",
                                              "--delete", "--inplace", "--compress", "--compress-choice=zstd", "--compress-level=5", m->containerPath + "/",
                                              "root@" + target->addr + ":" + dstDir});

            qStdOut() << "Backup to: " << target->name << ":" << dstDir << "\n";
            qStdOut().flush();

            runSshInteractive(m->ssh, params);

            if (lastExitCode != 0) {
                if (lastExitCode != RSYNC_VANISHED && vanishedOk == false) {
                    ret = false;
                } else {
                    runSsh(target, {"touch", targetDir + "/" + m->name + "/backup.touch"});
                }
                qInfo() << "Backup:" << m->name << "to" << target->name << "FAILED" << lastExitCode;
                qInfo() << params;
            } else {
                runSsh(target, {"touch", targetDir + "/" + m->name + "/backup.touch"});
            }
            if (targetDir.length()) {
                runSsh(m->ssh, {"scp", "/etc/systemd/nspawn/" + m->name + ".nspawn", "root@" + target->addr + ":" + targetDir + "/" + m->name + "/"});
            } else {
                runSsh(m->ssh,
                       {"scp", "/etc/systemd/nspawn/" + m->name + ".nspawn", "root@" + target->addr + ":/etc/systemd/nspawn/" + m->name + ".backup.nspawn"});
            }
            if (lastExitCode) {
                ret = false;
                qInfo() << "Backup of nspawn config file failed" << "/etc/systemd/nspawn/" + m->name + ".nspawn";
            }
            runSsh(m->ssh, {"test", "-f", "/etc/systemd/system/systemd-nspawn@" + m->name + ".service.d/override.conf"});
            if (lastExitCode == 0) {
                if (targetDir.length()) {
                    runSsh(m->ssh, {"scp", "/etc/systemd/system/systemd-nspawn@" + m->name + ".service.d/override.conf",
                                    "root@" + target->addr + ":" + targetDir + "/" + m->name + "/"});
                } else {
                    runSsh(m->ssh, {"rsync", "-avpx", "-e", "\"ssh -T -o Compression=no -x\"", "/etc/systemd//system/systemd-nspawn@" + m->name + ".service.d/",
                                    "root@" + target->addr + ":/etc/systemd/system/systemd-nspawn@" + m->name + ".backup.service.d/"});
                }
                if (lastExitCode) {
                    ret = false;
                    qInfo() << "Backup of nspawn service file failed" << "/etc/systemd/system/systemd-nspawn@" + m->name + ".service.d/override.conf";
                }
            }
        } else {
            QByteArray xml = runSsh(m->ssh, {"virsh", "dumpxml", m->name});
            if (lastExitCode != 0) {
                ret = false;
                qInfo() << "Unable to get VM definition";
                break;
            }
            if (targetDir.length() == 0) {
                for (QString img : m->vmImageList) {
                    QStringList params = QStringList({"rsync", "-aAXpx", "-e", "\"ssh -T -o Compression=no -x\"", "--progress", "--numeric-ids", "--whole-file",
                                                      "--no-devices", "--delete", "--inplace", "--compress", "--compress-choice=zstd", "--compress-level=5",
                                                      img, "root@" + target->addr + ":" + img});
                    qStdOut() << "Backup image: " << img << "to:" << target->name << "\n";
                    qStdOut().flush();
                    runSshInteractive(m->ssh, params);
                }
                QByteArray tmp = runSsh(target, {"tee", "/root/vm-" + m->name + ".backup.xml"}, false, xml);
                if (lastExitCode != 0) {
                    ret = false;
                    qInfo() << "Unable to write VM definition" << tmp << lastExitCode;
                }
            } else {
                for (QString img : m->vmImageList) {
                    QStringList params = QStringList({"rsync", "-aAXpx", "-e", "\"ssh -T -o Compression=no -x\"", "--progress", "--numeric-ids", "--whole-file",
                                                      "--no-devices", "--delete", "--inplace", "--compress", "--compress-choice=zstd", "--compress-level=5",
                                                      img, "root@" + target->addr + ":" + dstDir});
                    qStdOut() << "Backup image: " << img << " to: " << target->name << ":" << dstDir << "\n";
                    qStdOut().flush();
                    runSshInteractive(m->ssh, params);
                }
                QByteArray tmp = runSsh(target, {"tee", targetDir + "/" + m->name + "/vm.xml"}, false, xml);
                if (lastExitCode != 0) {
                    ret = false;
                    qInfo() << "Unable to write VM definition" << tmp << lastExitCode;
                }
            }
        }
    }
    return (ret);
}

bool terminateMachine(machine_t* m, bool wait = true) {
    QByteArray ret;
    if (m->type == "vm") {
        ret = runSsh(m->ssh, {"virsh", "destroy", m->name});
        if (lastExitCode != 0) {
            qInfo() << "Unable to stop vm";
            qInfo() << QString::fromUtf8(ret);
            return (false);
        }
        if (wait) {
            int counter = 0;
            bool running = true;
            while (running) {  // wait for real stop
                QStringList info = QString::fromUtf8(runSsh(m->ssh, {"virsh", "dominfo", m->name})).split("\n", Qt::SkipEmptyParts);
                for (const QString& s : info) {
                    if (s.startsWith("State") && !s.contains("running")) {
                        running = false;
                    }
                }
                QThread::msleep(25);
                counter += 25;
                if (counter > 10000) {
                    qInfo() << "Unable to stop:" << m->name;
                    return (false);
                }
            }
        }
    } else {
        ret = runSsh(m->ssh, {"machinectl", "terminate", m->name});
        if (lastExitCode != 0) {
            qInfo() << "Unable to stop container";
            qInfo() << QString::fromUtf8(ret);
            return (false);
        }
        if (wait) {
            int counter = 0;
            while (lastExitCode == 0) {  // wait for real stop
                runSsh(m->ssh, {"machinectl", "stop", m->name});
                QThread::msleep(25);
                counter += 25;
                if (counter > 10000) {
                    qInfo() << "Unable to stop:" << m->name;
                    return (false);
                }
            }
            lastExitCode = 0;
        }
    }
    if (lastExitCode != 0) {
        qInfo() << "Unable to stop machine";
        qInfo() << QString::fromUtf8(ret);
        return (-1);
    } else if (ret.length()) {
        qInfo() << QString::fromUtf8(ret);
    }
    m->status = "OFFLINE";
    return (true);
}

bool stopMachine(machine_t* m, bool wait = true) {
    QByteArray ret;
    if (m->type == "vm") {
        ret = runSsh(m->ssh, {"virsh", "shutdown", m->name});
        if (lastExitCode != 0) {
            qInfo() << "Unable to stop vm";
            qInfo() << QString::fromUtf8(ret);
            return (false);
        }
        if (wait) {
            int counter = 0;
            bool running = true;
            while (running) {  // wait for real stop
                QStringList info = QString::fromUtf8(runSsh(m->ssh, {"virsh", "dominfo", m->name})).split("\n", Qt::SkipEmptyParts);
                for (const QString& s : info) {
                    if (s.startsWith("State") && !s.contains("running")) {
                        running = false;
                    }
                }
                QThread::msleep(25);
                counter += 25;
                if (counter > 10000) {
                    qInfo() << "Unable to stop:" << m->name;
                    return (false);
                }
            }
        }
    } else {
        ret = runSsh(m->ssh, {"machinectl", "stop", m->name});
        if (lastExitCode != 0) {
            qInfo() << "Unable to stop container";
            qInfo() << QString::fromUtf8(ret);
            return (false);
        }
        if (wait) {
            int counter = 0;
            while (lastExitCode == 0) {  // wait for real stop
                runSsh(m->ssh, {"machinectl", "stop", m->name});
                QThread::msleep(25);
                counter += 25;
                if (counter > 10000) {
                    qInfo() << "Unable to stop:" << m->name;
                    return (false);
                }
            }
            lastExitCode = 0;
        }
    }
    if (lastExitCode != 0) {
        qInfo() << "Unable to stop machine";
        qInfo() << QString::fromUtf8(ret);
        return (-1);
    } else if (ret.length()) {
        qInfo() << QString::fromUtf8(ret);
    }
    m->status = "OFFLINE";
    return (true);
}

bool startMachine(machine_t* m, bool wait = false) {
    QByteArray ret;
    if (m->type == "vm") {
        ret = runSsh(m->ssh, {"virsh", "start", m->name});
    } else {
        ret = runSsh(m->ssh, {"machinectl", "start", m->name});
    }
    if (lastExitCode != 0) {
        qInfo() << "Unable to start machine";
        qInfo() << QString::fromUtf8(ret);
        return (-1);
    } else if (ret.length()) {
        qInfo() << QString::fromUtf8(ret);
    }
    m->status = "ONLINE";
    return (true);
}

bool disableMachine(machine_t* m) {
    QByteArray ret;
    if (m->type == "vm") {
        ret = runSsh(m->ssh, {"virsh", "autostart", m->name, "--disable"});
    } else {
        ret = runSsh(m->ssh, {"machinectl", "disable", m->name});
    }
    if (lastExitCode != 0) {
        qInfo() << "Unable to disable machine";
        qInfo() << QString::fromUtf8(ret);
        return (-1);
    } else if (ret.length()) {
        qInfo() << QString::fromUtf8(ret);
    }
    return (true);
}

bool removeMachine(machine_t* m) {
    QByteArray ret;
    if (!askYes("Really remove machine: '" + m->name + "'?")) {
        return (false);
    }
    if (m->status == "ONLINE") {
        qInfo() << "Stopping running machine";
        if (!stopMachine(m, true)) {
            return (false);
        }
    }
    if (m->type == "vm") {
        ret = runSsh(m->ssh, {"virsh", "undefine", m->name, "--managed-save", "--remove-all-storage", "--snapshots-metadata"});
    } else {
        ret = runSsh(m->ssh, {"machinectl", "remove", m->name});
    }
    if (lastExitCode != 0) {
        qInfo() << "Unable to remove machine";
        qInfo() << QString::fromUtf8(ret);
        return (-1);
    } else if (ret.length()) {
        qInfo() << QString::fromUtf8(ret);
    }
    return (true);
}

bool enableMachine(machine_t* m) {
    QByteArray ret;
    if (m->type == "vm") {
        ret = runSsh(m->ssh, {"virsh", "autostart", m->name});
    } else {
        ret = runSsh(m->ssh, {"machinectl", "enable", m->name});
    }
    if (lastExitCode != 0) {
        qInfo() << "Unable to enable machine";
        qInfo() << QString::fromUtf8(ret);
        return (-1);
    } else if (ret.length()) {
        qInfo() << QString::fromUtf8(ret);
    }
    return (true);
}

bool renameMachine(QString srcName, QString dstName, ssh_t* ssh) {
    QByteArray ret;
    if (dstName.contains(" ")) {
        qInfo() << "Spaces in container name are not allowed" << dstName;
        return false;
    }
    machine_t* check = findMachine(srcName, ssh);
    if (check == nullptr) {
        qInfo() << "Machine not exists:" << srcName;
        return false;
    }
    machine_t* test = findMachine(dstName, ssh);
    if (test != nullptr && test->ssh->name == ssh->name) {
        qInfo() << "Target machine already exists:" << dstName;
        return false;
    }
    bool isOnline = check->status == "ONLINE";
    if (isOnline) {
        if (!askYes("Machine '" + srcName + "' is running. Stop to rename?")) {
            return false;
        }
        qInfo() << "Trying to stop machine";
        if (!stopMachine(check, true)) {
            qInfo() << "Unable to stop machine";
            return false;
        }
    }
    if (check->type != "container") {
        ret = runSsh(ssh, {"virsh", "domrename", srcName, dstName});
        if (lastExitCode != 0) {
            qInfo() << "Unable to rename VM";
            qInfo() << QString::fromUtf8(ret);
            return false;
        } else if (ret.length()) {
            qInfo() << QString::fromUtf8(ret);
        }
    } else {
        ret = runSsh(ssh, {"machinectl", "rename", srcName, dstName});
        if (lastExitCode == 0) {
            runSsh(ssh, {"test", "-f", "/etc/systemd/system/systemd-nspawn@" + srcName + ".service.d/override.conf"});
            if (lastExitCode == 0) {
                runSsh(ssh, {"mv", "/etc/systemd//system/systemd-nspawn@" + srcName + ".service.d/",
                             "/etc/systemd/system/systemd-nspawn@" + dstName + ".backup.service.d/"});
                if (lastExitCode != 0) {
                    qInfo() << "Unable to rename service.d";
                    return (-1);
                }
            }
        } else {
            qInfo() << "Unable to rename container";
            qInfo() << QString::fromUtf8(ret);
            return false;
        }
    }
    check->name = dstName;
    if (isOnline) {
        qInfo() << "Trying to start renamed VM";
        startMachine(check);
        enableMachine(check);
    }
    return (true);
}

void printTable(QList<QStringList> table, QStringList header) {
    QList<int> columnLengths;

    // get base column lengths from header
    foreach (const QString& s, header) {
        columnLengths << s.length() + 2;
    }

    // get max column lengths from rows
    foreach (const QStringList& row, table) {
        if (row.length() < columnLengths.length()) {
            qInfo() << "Too short row" << row;
            continue;
        }
        for (int i = 0; i < row.length(); i++) {
            if (columnLengths.count() <= i) {
                qInfo() << "Too much columns in row:" << row;
                break;
            }
            columnLengths[i] = qMax(columnLengths[i], row[i].length() + 2);
        }
    }

    // print rows
    table.insert(0, header);
    qStdOut() << BACKGROUND_BLUE;
    foreach (const QStringList& row, table) {
        for (int i = 0; i < row.length(); i++) {
            if (columnLengths.count() <= i) {
                break;
            }
            int len = row[i].length() + 2;
            if (colorAssociation.contains(row[i])) {
                qStdOut() << colorAssociation[row[i]] << row[i] << COLOR_OFF << "  ";
            } else {
                qStdOut() << row[i] << "  ";
            }
            while (len < columnLengths[i]) {
                qStdOut() << " ";
                len++;
            }
        }
        qStdOut() << COLOR_OFF << "\n";
    }
}

inline void swap(QJsonValueRef v1, QJsonValueRef v2) {
    QJsonValue tmp(v1);
    v1 = QJsonValue(v2);
    v2 = tmp;
}

int processCommand(QStringList args) {
    if (!args.count()) {
        return (0);
    }
    QString command = args.takeFirst();
    if (command == "hosts") {
        QList<QStringList> table;
        QStringList header;
        header = QStringList{"MACHINE", "ADDR", "ARCH", "BRIDGES", "VM's (total,used,%)", "Containers", "Machines"};
        std::sort(sshConnList.begin(), sshConnList.end(), [](ssh_t* m1, ssh_t* m2) { return (m1->name.toLower() < m2->name.toLower()); });
        for (auto s : sshConnList) {
            QStringList line;
            line << s->name << s->addr << s->arch << s->bridges.join(" ");
            for (int i = 0; i < 3; i++) {
                if (s->space.count() > i) {
                    line << QString("%1, %2, %3%")
                                .arg(s->space[i].total, 5, 'f', 0, ' ')
                                .arg(s->space[i].used, 5, 'f', 0, ' ')
                                .arg((s->space[i].used * 100) / s->space[i].total, 3, 'f', 0, ' ');
                } else {
                    line << "";
                }
            }
            table << line;
        }
        printTable(table, header);
    } else if (command == "list") {
        QList<QStringList> table;
        QStringList header;
        if (showextended) {
            header = QStringList{"MACHINE", "HOST", "TYPE", "STATUS", "ADDRESSES", "OS", "ARCH", "INTERFACES", "PATH/DRIVE"};
        } else {
            header = QStringList{"MACHINE", "HOST", "TYPE", "STATUS", "ADDRESSES", "OS"};
        }
        std::sort(machineList.begin(), machineList.end(), [](machine_t* m1, machine_t* m2) {
            if (m1->name.toLower() == m2->name.toLower()) {
                return (m1->ssh->name.toLower() < m2->ssh->name.toLower());
            }
            return (m1->name.toLower() < m2->name.toLower());
        });
        foreach (auto m, machineList) {
            QStringList addresses;
            QStringList path;
            QStringList interfaces = m->interfaces;
            if (m->name.endsWith(".backup") && showBackups == false) {
                continue;
            }
            foreach (const QString& s, m->addresses.split("\n", Qt::SkipEmptyParts)) {
                if (!s.contains(":")) {
                    addresses << s;
                }
            }
            if (m->type == "container") {
                path << m->containerPath;
            } else {
                path = m->vmBaseImageList;
            }
            int lines = qMax(path.count(), addresses.count());
            if (showextended) {
                for (int i = 0; i < lines; i++) {
                    QStringList row;
                    QString a;
                    QString p;
                    QString ii;
                    QString blank;
                    if (addresses.count()) {
                        a = addresses.takeFirst();
                    }
                    if (path.count()) {
                        p = path.takeFirst();
                    }
                    if (interfaces.count()) {
                        ii = interfaces.takeFirst();
                    }
                    if (i == 0) {
                        row << m->name << m->ssh->name << m->type << m->status << a << m->os << m->ssh->arch << ii << p;
                    } else {
                        row << blank << blank << blank << blank << a << blank << blank << ii << p;
                    }
                    table << row;
                }
            } else {
                QStringList row;
                row << m->name << m->ssh->name << m->type << m->status << addresses.join(" ") << m->os;
                table << row;
            }
        }
        printTable(table, header);
    } else if (QStringList({"start", "stop", "kill", "enable", "disable", "remove", "restart", "spread", "backup", "exec"}).contains(command)) {
        if (args.length()) {
            QStringList targetList = args.takeFirst().split(",", Qt::SkipEmptyParts);
            foreach (QString name, targetList) {
                machine_t* m = findMachine(name);
                if (m == nullptr) {
                    qInfo() << "Machine lookup error:" << name;
                    continue;
                } else {
                    qInfo() << "Processing:" << command << "on" << name << "(" + m->ssh->name + ")";
                    if (command == "remove") {
                        removeMachine(m);
                    } else if (command == "start") {
                        startMachine(m);
                    } else if (command == "stop") {
                        stopMachine(m);
                    } else if (command == "kill") {
                        terminateMachine(m);
                    } else if (command == "restart") {
                        if (m->status == "ONLINE") {
                            if (!stopMachine(m, true)) {
                                continue;
                            }
                        }
                        startMachine(m);
                    } else if (command == "enable") {
                        enableMachine(m);
                    } else if (command == "disable") {
                        disableMachine(m);
                    } else if (command == "backup") {
                        QElapsedTimer timer, timer2;
                        timer.start();
                        if (args.length() < 1) {
                            qInfo() << "Target is missing";
                            return (-1);
                        }
                        QStringList tmp = args.first().split(":", Qt::SkipEmptyParts);
                        QString targetDir;
                        if (tmp.length() == 2) {
                            targetDir = tmp[1];
                        } else {
                            qInfo() << "backup to selected host only";
                        }
                        ssh_t* t = findSsh(tmp[0]);
                        if (t == nullptr) {
                            qInfo() << "Target not exists:" << name;
                            return (-1);
                        }
                        qInfo() << "Backup:" << name;
                        bool isOnline = m->status == "ONLINE";
                        if (m->type == "container" || !isOnline) {
                            backupMachine(m, t, targetDir);
                        }
                        if (isOnline) {
                            if (!askYes("Machine '" + name + "' is running. Stop to full offline backup?")) {
                                continue;
                            }
                            timer2.start();
                            qInfo() << "Live backup DONE. Stopping for offline aftersync";
                            if (!stopMachine(m, true)) {
                                qInfo() << "Unable to stop machine";
                                return (-1);
                            }
                            backupMachine(m, t, targetDir);
                            startMachine(m);
                            qInfo() << "Backup DONE.";
                        } else {
                            qInfo() << "Backup DONE.";
                        }
                        qInfo() << "Backup finished in:" << (static_cast<double>(timer.elapsed()) / 1000)
                                << "seconds, Downtine:" << (static_cast<double>(timer2.elapsed()) / 1000) << "seconds";
                    } else if (command == "spread") {
                        QElapsedTimer timer, timer2;
                        timer.start();
                        qInfo() << "Spread:" << name;
                        bool isOnline = m->status == "ONLINE";
                        if (m->type == "container" || !isOnline) {
                            backupMachine(m);
                        }
                        if (isOnline) {
                            if (!askYes("Machine '" + name + "' is running. Stop to full offline spread?")) {
                                continue;
                            }
                            timer2.start();
                            qInfo() << "Live backup DONE. Stopping for offline aftersync";
                            if (!stopMachine(m, true)) {
                                qInfo() << "Unable to stop machine";
                                return (-1);
                            }
                            backupMachine(m);
                            startMachine(m);
                            qInfo() << "Spread DONE.";
                        } else {
                            qInfo() << "Spread DONE.";
                        }
                        qInfo() << "Spread finished in:" << (static_cast<double>(timer.elapsed()) / 1000)
                                << "seconds, Downtine:" << (static_cast<double>(timer2.elapsed()) / 1000) << "seconds";
                    } else if (command == "exec") {
                        if (args.length() < 2) {
                            qInfo() << "Exec needs container[s] and command [args]";
                            return (-1);
                        }
                        qInfo() << "Starting command on:" << name;
                        runSsh(m->ssh,
                               QStringList({
                                   "systemd-run",
                                   "--wait",
                                   "-P",
                                   "-q",
                                   "-M",
                                   name,
                               }) << args,
                               true);
                    }
                }
            }
        } else {
            qInfo() << "Machine name missing for start";
        }
    } else if (command == "clone") {
        if (args.length() != 2) {
            qInfo() << "Clone needs both source and clone_name parameters";
            return (-1);
        }
        QString name = args.takeFirst();
        QString dst = args.takeFirst();
        machine_t* m = findMachine(name);
        if (m == nullptr) {
            qInfo() << "Machine lookup error:" << name;
            return (-1);
        }
        QByteArray ret = runSsh(m->ssh, {"machinectl", command, name, dst});
        if (ret.length()) {
            qInfo() << QString::fromUtf8(ret);
        }
    } else if (command == "rename") {
        if (args.length() < 2) {
            qInfo() << "Rename source or target is missing";
            return (-1);
        }
        QString srcName = args.takeFirst();
        QString dstName = args.takeFirst();
        machine_t* m = findMachine(srcName);
        renameMachine(srcName, dstName, m->ssh);
    } else if (command == "move") {
        QElapsedTimer timer, timer2;
        timer.start();
        if (args.length() < 2) {
            qInfo() << "Machine name or destination is missing";
            return (-1);
        }
        QString name = args.takeFirst();
        QString target = args.takeFirst();
        machine_t* m = findMachine(name);
        ssh_t* t = findSsh(target);
        if (m == nullptr) {
            qInfo() << "Machine not exists:" << name;
            return (-1);
        }
        if (t == nullptr) {
            qInfo() << "Target not exists:" << name;
            return (-1);
        }
        if (m->ssh->arch != t->arch) {
            qInfo() << "Architexture:" << m->ssh->arch << "and" << t->arch << "differs";
            return (-1);
        }
        bool isOnline = m->status == "ONLINE";
        if (m->ssh->addr == t->addr) {
            qInfo() << "can't move to same host" << t->name;
            return (-1);
        }
        if (m->type == "container") {
            if (!backupMachine(m, t, "", true)) {
                qInfo() << "Live backup failed" << name;
                return (-1);
            }
        }
        if (isOnline) {
            qInfo() << "Live backup DONE. Stopping for offline aftersync";
            timer2.start();
            stopMachine(m, true);
            if (!backupMachine(m, t)) {
                qInfo() << "offline backup failed" << name;
                return (-1);
            }
            qInfo() << "Aftersync DONE";
        }
        // disable and rename on original
        if (!disableMachine(m)) {
            return -1;
        }

        //reload machine list
        getMachineList();
        //find again
        m = findMachine(name);
        // rename target and enable if needed
        if (m->type == "container") {
            if (!renameMachine(name, name + ".backup", m->ssh)) {
                return -1;
            }
            if (!renameMachine(name + ".backup", name, t)) {
                return -1;
            }
        } else {
            // undefine on old host
            QByteArray result = runSsh(m->ssh, {"virsh", "undefine", name});
            if (lastExitCode != 0) {
                qInfo() << "Unable to define vm" << result;
                return (-1);
            }
            // create on new host
            result = runSsh(t, {"virsh", "define", "/root/vm-" + name + ".backup.xml"});
            if (lastExitCode != 0) {
                qInfo() << "Unable to define vm" << result;
                return (-1);
            }
        }

        // must at first relod machine list
        getMachineList();
        // get new and find proper one to enable and start
        m = findMachine(name);

        if (isOnline && m) {
            qInfo() << "Starting container on host:" << target;
            enableMachine(m);
            startMachine(m);
            if (lastExitCode != 0) {
                qInfo() << "Unable to enable container";
                return (-1);
            }
        }
        qInfo() << "Move finished in:" << (static_cast<double>(timer.elapsed()) / 1000)
                << "seconds, Downtine:" << (static_cast<double>(timer2.elapsed()) / 1000) << "seconds";
    } else {
        qInfo() << "Unknown command:" << command;
    }
    return (0);
}

void log_callback(int level, const char* function, const char* msg, void* userdata) {
    //    qInfo() << "ssh log" << level << msg;
}

int main(int argc, char* argv[]) {
    QCoreApplication a(argc, argv);
    QStringList args = a.arguments();

    ssh_set_log_callback(log_callback);

    if (args.contains("-h")) {
        qStdOut() << "Usage: " << args.first() << HELP_BASE << HELP_COMMANDS;
        return (0);
    }
    args.takeFirst();  // remove program name
    if (args.contains("-y")) {
        dontAsk = true;
        args.removeAll("-y");
    }
    if (args.contains("-n")) {
        allNo = true;
        args.removeAll("-n");
    }
    if (args.contains("-e")) {
        showextended = true;
        args.removeAll("-e");
    }

    QString config = QProcessEnvironment::systemEnvironment().value("HOME", "") + "/.ccc.json";
    if (args.count() > 1 && args.first() == "-c") {
        args.takeFirst();
        config = args.takeFirst();
    }
    if (args.count() > 0 && args.first() == "-a") {
        args.takeFirst();
        showBackups = true;
    }
    QFile configFile(config);
    QJsonObject configObject;
    if (!configFile.open(QIODevice::ReadOnly)) {
        qInfo() << "Unable to open config, trying builtin for localhost:" << config;
        configObject = QJsonDocument::fromJson(defaultConfig).object();
    } else {
        if (configFile.size() > (1024 * 32)) {
            qInfo() << "Config file too long" << config;
            return (-1);
        }
        configObject = QJsonDocument::fromJson(configFile.readAll()).object();
    }
    QJsonArray hosts = configObject.value("hosts").toArray();
    if (hosts.count() == 0) {
        qInfo() << "Hosts are empty";
        return (-1);
    }
    std::sort(hosts.begin(), hosts.end(), [](const QJsonValue& v1, const QJsonValue& v2) {
        if (!v1.isObject() || !v2.isObject()) {
            return (false);
        }
        QJsonObject o1 = v1.toObject();
        QJsonObject o2 = v2.toObject();

        return (o1.value("name").toString() < o2.value("name").toString());
    });
    sshKeyPath = configObject.value("sshKeyPath").toString();
    QJsonObject colors = configObject.value("colors").toObject();
    foreach (const QString& key, colors.keys()) {
        if (colorTable.contains(colors.value(key).toString())) {
            colorAssociation.insert(key, colorTable[colors.value(key).toString()]);
        }
    }

    if (args.count() && args.first() == "help") {
        qStdOut() << "Usage: " << args.first() << HELP_BASE << HELP_COMMANDS;
        return (0);
    }

    if (!sshConnect(hosts)) {
        return (-1);
    }
    getMachineList();
    if (args.count() == 0) {
        args << "list";
    }
    if (args.first() != "shell") {
        return (processCommand(args));
    } else {
        QString lastCommand;
        while (!qStdIn().atEnd()) {
            qStdOut() << "#> ";
            qStdOut().flush();
            QString line = QString::fromUtf8(qStdIn().readLine(1024));
            line.remove("\n");
            if (line == "quit" || line == "q") {
                break;
            }
            lastCommand = line;
            args = line.split(" ", Qt::SkipEmptyParts);
            if (args.count()) {
                if (args.first() == "help") {
                    qStdOut() << HELP_COMMANDS;
                } else {
                    processCommand(args);
                }
            }
        }
        qStdOut() << "\n";
        qStdOut().flush();
    }
}
