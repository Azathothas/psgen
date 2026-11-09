//! The embedded process corpus.
//!
//! Every entry is a command line observed on a real Linux system or taken
//! verbatim from a distribution's own unit file or documented invocation.
//! Nothing here is a placeholder word and nothing here is drawn from the
//! cryptocurrency, botnet, brute force or credential dumping modules that
//! genact and fakeact ship; those families are deliberately absent and the
//! `check` subcommand re-verifies their absence.
//!
//! Placeholders are expanded by `gen`:
//! `{hex6}`, `{hex8}`, `{hex12}`, `{hex64}`, `{n}`, `{n2}`, `{pid}`,
//! `{port}`, `{cport}`, `{ip}`, `{uid}`, `{user}`.

pub const FAM_SYS: u8 = 0;
pub const FAM_WEB: u8 = 1;
pub const FAM_DB: u8 = 2;
pub const FAM_CTR: u8 = 3;
pub const FAM_DEV: u8 = 4;
pub const FAM_MON: u8 = 5;
pub const FAM_STO: u8 = 6;
pub const FAM_MAIL: u8 = 7;
pub const FAM_DESK: u8 = 8;
pub const FAM_NET: u8 = 9;

pub const F_SESSION: u8 = 1;
pub const F_THREADS: u8 = 2;
pub const F_TTY: u8 = 4;
pub const F_BUSY: u8 = 8;
pub const F_LONG: u8 = 16;
pub const F_SHORT: u8 = 32;
pub const F_CHILD: u8 = 64;

/// The command runs as whoever invoked `psgen`; substituted at generation.
pub const SELF_USER: &str = "@self";

pub struct Tmpl {
    pub cmd: &'static str,
    pub user: &'static str,
    pub fam: u8,
    pub vsz: u32,
    pub rss: u32,
    pub cpu: u16,
    pub inst: u8,
    pub flags: u8,
    pub weight: u8,
}

macro_rules! t {
    ($cmd:expr, $user:expr, $fam:expr, $vsz:expr, $rss:expr, $cpu:expr, $inst:expr, $flags:expr, $w:expr) => {
        Tmpl {
            cmd: $cmd,
            user: $user,
            fam: $fam,
            vsz: $vsz,
            rss: $rss,
            cpu: $cpu,
            inst: $inst,
            flags: $flags,
            weight: $w,
        }
    };
}

pub static CORPUS: &[Tmpl] = &[
    // ---- system ------------------------------------------------------------
    t!("/sbin/init", "root", FAM_SYS, 23868, 14748, 3, 1, F_SESSION, 30),
    t!("/usr/lib/systemd/systemd-journald", "root", FAM_SYS, 51120, 17464, 1, 1, F_SESSION, 22),
    t!("/usr/lib/systemd/systemd-udevd", "root", FAM_SYS, 32040, 9176, 0, 1, F_SESSION, 16),
    t!("/usr/lib/systemd/systemd-resolved", "systemd-resolve", FAM_SYS, 23364, 14516, 0, 1, F_SESSION, 12),
    t!("/usr/lib/systemd/systemd-networkd", "systemd-network", FAM_SYS, 20660, 10828, 0, 1, F_SESSION, 12),
    t!("/usr/lib/systemd/systemd-logind", "root", FAM_SYS, 18952, 9160, 0, 1, F_SESSION, 12),
    t!("/usr/lib/systemd/systemd-timesyncd", "systemd-timesync", FAM_SYS, 18304, 8344, 0, 1, F_SESSION, 10),
    t!("/usr/lib/systemd/systemd-machined", "root", FAM_SYS, 19000, 9000, 0, 1, F_SESSION, 5),
    t!("/usr/lib/systemd/systemd-hostnamed", "root", FAM_SYS, 17000, 8000, 0, 1, F_SESSION, 3),
    t!("/usr/lib/systemd/systemd-coredump", "root", FAM_SYS, 30000, 12000, 0, 1, F_SESSION, 3),
    t!("/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only", "messagebus", FAM_SYS, 8368, 5080, 0, 1, F_SESSION, 14),
    t!("/usr/bin/dbus-daemon --session --address=unix:path=/run/user/{uid}/bus", "@self", FAM_SYS, 8400, 4600, 0, 1, F_CHILD, 8),
    t!("/usr/sbin/cron -f", "root", FAM_SYS, 6876, 2984, 0, 1, F_SESSION, 14),
    t!("/usr/sbin/rsyslogd -n -iNONE", "syslog", FAM_SYS, 12800, 5200, 1, 1, F_SESSION, 14),
    t!("sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups", "root", FAM_SYS, 11772, 7860, 0, 1, F_SESSION, 18),
    t!("sshd: {user} [priv]", "root", FAM_SYS, 11800, 7900, 0, 2, F_CHILD, 10),
    t!("sshd: {user}@pts/{n}", "@self", FAM_SYS, 11800, 7900, 0, 1, F_TTY | F_CHILD, 12),
    t!("/usr/lib/systemd/systemd --user", "@self", FAM_SYS, 34000, 15000, 0, 1, F_CHILD, 12),
    t!("(sd-pam)", "@self", FAM_SYS, 40000, 3000, 0, 1, F_CHILD, 8),
    t!("/usr/sbin/agetty -o -p -- \\u --noclear tty{n} linux", "root", FAM_SYS, 7772, 2924, 0, 1, F_SESSION | F_TTY, 6),
    t!("/usr/sbin/irqbalance --foreground", "root", FAM_SYS, 15400, 6400, 1, 1, F_SESSION, 6),
    t!("/usr/libexec/polkitd --no-debug", "root", FAM_SYS, 22400, 9800, 0, 1, F_SESSION, 6),
    t!("/usr/sbin/chronyd", "_chrony", FAM_SYS, 15200, 5400, 0, 1, F_SESSION, 6),
    t!("/usr/sbin/atd -f", "root", FAM_SYS, 6600, 2800, 0, 1, F_SESSION, 4),
    t!("/usr/sbin/smartd -n -q never", "root", FAM_SYS, 26000, 9000, 0, 1, F_SESSION, 4),
    t!("/usr/sbin/haveged -w 1024 -v 1", "root", FAM_SYS, 12000, 3000, 5, 1, F_SESSION, 3),
    t!("/usr/sbin/thermald --systemd --dbus-enable", "root", FAM_SYS, 30000, 12000, 0, 1, F_SESSION, 3),
    t!("/usr/lib/accountsservice/accounts-daemon", "root", FAM_SYS, 28000, 11000, 0, 1, F_SESSION, 4),
    t!("/usr/lib/upower/upowerd", "root", FAM_SYS, 24000, 9000, 0, 1, F_SESSION, 3),
    t!("/usr/sbin/ModemManager", "root", FAM_SYS, 30000, 11000, 0, 1, F_SESSION, 3),
    t!("/usr/lib/bluetooth/bluetoothd", "root", FAM_SYS, 20000, 8000, 0, 1, F_SESSION, 3),
    t!("/usr/bin/systemd-tmpfiles --create --remove --boot --exclude-prefix=/dev", "root", FAM_SYS, 12000, 4000, 200, 1, F_BUSY, 4),

    // ---- web ---------------------------------------------------------------
    t!("nginx: master process /usr/sbin/nginx -g daemon on; master_process on;", "root", FAM_WEB, 14628, 8904, 0, 1, 0, 16),
    t!("nginx: worker process", "www-data", FAM_WEB, 16496, 5040, 0, 6, F_CHILD, 30),
    t!("nginx: cache manager process", "www-data", FAM_WEB, 16496, 5000, 0, 1, F_CHILD, 6),
    t!("apache2 -DFOREGROUND", "root", FAM_WEB, 102000, 21000, 0, 1, F_SESSION, 8),
    t!("apache2 -k start", "www-data", FAM_WEB, 124000, 26000, 0, 5, F_CHILD, 20),
    t!("php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)", "root", FAM_WEB, 62300, 21000, 0, 1, F_SESSION, 8),
    t!("php-fpm: pool www", "www-data", FAM_WEB, 74200, 31000, 1, 4, F_CHILD, 14),
    t!("gunicorn: master [app:app]", "www-data", FAM_WEB, 61200, 25400, 0, 1, F_SESSION, 8),
    t!("gunicorn: worker [app:app]", "www-data", FAM_WEB, 124000, 52000, 2, 3, F_THREADS | F_CHILD, 12),
    t!("/usr/sbin/haproxy -Ws -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid", "haproxy", FAM_WEB, 82000, 21000, 0, 1, F_SESSION | F_THREADS, 5),
    t!("/usr/bin/envoy -c /etc/envoy/envoy.yaml --service-cluster edge --service-node node{n}", "envoy", FAM_WEB, 204000, 62000, 1, 1, F_SESSION | F_THREADS, 4),
    t!("/usr/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile", "caddy", FAM_WEB, 104000, 32000, 0, 1, F_SESSION | F_THREADS, 4),
    t!("/usr/bin/traefik --configFile=/etc/traefik/traefik.yml", "root", FAM_WEB, 96000, 26000, 0, 1, F_SESSION | F_THREADS, 3),
    t!("/usr/sbin/varnishd -F -a :6081 -f /etc/varnish/default.vcl -s malloc,256m", "varnish", FAM_WEB, 306000, 82000, 1, 1, F_SESSION | F_THREADS, 3),
    t!("/usr/bin/unitd --no-daemon --control unix:/var/run/control.unit.sock", "root", FAM_WEB, 64000, 16000, 0, 1, F_SESSION | F_THREADS, 2),

    // ---- database ----------------------------------------------------------
    t!("/usr/lib/postgresql/17/bin/postgres -D /var/lib/postgresql/17/main -c config_file=/etc/postgresql/17/main/postgresql.conf", "postgres", FAM_DB, 217880, 30284, 0, 1, F_SESSION, 12),
    t!("postgres: 17/main: checkpointer ", "postgres", FAM_DB, 218036, 6224, 0, 1, F_LONG | F_CHILD, 10),
    t!("postgres: 17/main: background writer ", "postgres", FAM_DB, 218020, 7648, 0, 1, F_LONG | F_CHILD, 10),
    t!("postgres: 17/main: walwriter ", "postgres", FAM_DB, 218020, 10464, 0, 1, F_LONG | F_CHILD, 10),
    t!("postgres: 17/main: autovacuum launcher ", "postgres", FAM_DB, 219476, 9444, 0, 1, F_LONG | F_CHILD, 10),
    t!("postgres: 17/main: logical replication launcher ", "postgres", FAM_DB, 219484, 8576, 0, 1, F_LONG | F_CHILD, 10),
    t!("postgres: 17/main: app app {ip}({cport}) idle", "postgres", FAM_DB, 220112, 12100, 0, 4, F_CHILD, 18),
    t!("postgres: 17/main: app app {ip}({cport}) SELECT", "postgres", FAM_DB, 220112, 18400, 80, 2, F_BUSY | F_CHILD, 10),
    t!("postgres: 17/main: archiver ", "postgres", FAM_DB, 218020, 7000, 0, 1, F_LONG | F_CHILD, 6),
    t!("/usr/sbin/mysqld --defaults-file=/etc/mysql/mysql.conf.d/mysqld.cnf", "mysql", FAM_DB, 1240000, 408000, 1, 1, F_SESSION | F_THREADS, 8),
    t!("/usr/sbin/mariadbd --defaults-file=/etc/mysql/mariadb.cnf", "mysql", FAM_DB, 1100000, 302000, 1, 1, F_SESSION | F_THREADS, 6),
    t!("/usr/bin/redis-server 127.0.0.1:6379", "redis", FAM_DB, 76328, 17440, 4, 1, F_SESSION | F_THREADS, 12),
    t!("/usr/bin/redis-server *:6379", "redis", FAM_DB, 76328, 17440, 4, 1, F_SESSION | F_THREADS, 6),
    t!("/usr/bin/mongod --config /etc/mongod.conf", "mongodb", FAM_DB, 1540000, 204000, 2, 1, F_SESSION | F_THREADS, 6),
    t!("/usr/bin/memcached -m 64 -p 11211 -u memcache -l 127.0.0.1", "memcache", FAM_DB, 40200, 10400, 0, 1, F_SESSION | F_THREADS, 6),
    t!("/usr/bin/clickhouse-server --config-file=/etc/clickhouse-server/config.xml", "clickhouse", FAM_DB, 2100000, 308000, 3, 1, F_SESSION | F_THREADS, 3),
    t!("/usr/bin/etcd --name default --data-dir /var/lib/etcd", "etcd", FAM_DB, 204000, 52000, 1, 1, F_SESSION | F_THREADS, 5),

    // ---- containers and virtualisation -------------------------------------
    t!("/usr/bin/containerd", "root", FAM_CTR, 2168420, 48544, 1, 1, F_SESSION | F_THREADS, 14),
    t!("/usr/sbin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock", "root", FAM_CTR, 2284708, 88256, 2, 1, F_SESSION | F_THREADS, 14),
    t!("containerd-shim-runc-v2 -namespace moby -id {hex64} -address /run/containerd/containerd.sock", "root", FAM_CTR, 12400, 4100, 0, 3, F_THREADS | F_CHILD, 16),
    t!("/usr/bin/containerd-shim-runc-v2 -namespace moby -id {hex64} -address /run/containerd/containerd.sock", "root", FAM_CTR, 12400, 4100, 0, 3, F_THREADS | F_CHILD, 12),
    t!("docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port {port} -container-ip 172.17.0.2 -container-port 80", "root", FAM_CTR, 12400, 4200, 0, 2, F_THREADS | F_CHILD, 6),
    t!("/usr/bin/containerd-shim-runc-v2 -namespace k8s.io -id {hex64} -address /run/containerd/containerd.sock", "root", FAM_CTR, 12400, 4100, 0, 4, F_THREADS, 8),
    t!("/usr/bin/kubelet --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf --config=/var/lib/kubelet/config.yaml", "root", FAM_CTR, 312000, 82000, 3, 1, F_SESSION | F_THREADS, 5),
    t!("/usr/bin/kube-proxy --config=/var/lib/kube-proxy/config.conf --hostname-override=node1", "root", FAM_CTR, 124000, 31000, 1, 1, F_SESSION | F_THREADS, 4),
    t!("/usr/bin/coredns -conf /etc/coredns/Corefile", "root", FAM_CTR, 32000, 11000, 1, 1, F_SESSION | F_THREADS, 4),
    t!("/usr/bin/flanneld --ip-masq --kube-subnet-mgr", "root", FAM_CTR, 82000, 21000, 0, 1, F_SESSION | F_THREADS, 3),
    t!("/usr/bin/calico-node -felix", "root", FAM_CTR, 154000, 41000, 2, 1, F_SESSION | F_THREADS, 3),
    t!("/usr/bin/firecracker --api-sock /run/firecracker.sock", "root", FAM_CTR, 52000, 15400, 1, 1, F_THREADS, 3),
    t!("qemu-system-x86_64 -enable-kvm -m 4096 -smp 4 -cpu host -drive file=/var/lib/libvirt/images/vm{n}.qcow2,format=qcow2", "libvirt-qemu", FAM_CTR, 4200000, 2080000, 12, 1, F_THREADS, 3),
    t!("/usr/sbin/libvirtd --daemon", "root", FAM_CTR, 102000, 26000, 0, 1, F_SESSION | F_THREADS, 4),
    t!("/usr/sbin/virtlogd", "root", FAM_CTR, 30000, 8200, 0, 1, F_SESSION | F_THREADS, 3),
    t!("/usr/bin/lxc-start -F -n web0{n}", "root", FAM_CTR, 52000, 15400, 0, 1, F_THREADS, 2),

    // ---- development and build ---------------------------------------------
    t!("gcc -c -O2 -Wall -Wextra -march=x86-64 -pipe -Idrivers/net -DDEBUG -o drivers/net/e1000.o", "@self", FAM_DEV, 102000, 21000, 920, 1, F_BUSY, 10),
    t!("gcc -c -O2 -Wall -Wextra -march=x86-64 -pipe -Ifs/cifs -DDEBUG -D_REENTRANT -o fs/cifs/cifsfs.o", "@self", FAM_DEV, 104000, 22000, 880, 1, F_BUSY, 8),
    t!("make -j8", "@self", FAM_DEV, 32000, 10400, 450, 1, F_SHORT, 8),
    t!("make modules_install", "root", FAM_DEV, 30000, 8200, 12, 1, F_SHORT, 4),
    t!("cargo build --release", "@self", FAM_DEV, 512000, 102000, 600, 1, F_THREADS | F_SHORT, 10),
    t!("cargo run --release --bin server", "@self", FAM_DEV, 512000, 102000, 40, 1, F_THREADS | F_LONG, 6),
    t!("rustc --crate-name app src/main.rs --edition=2021 --crate-type bin -C opt-level=3 -C embed-bitcode=no", "@self", FAM_DEV, 308000, 82000, 700, 1, F_BUSY, 6),
    t!("node /app/server.js", "@self", FAM_DEV, 512000, 62000, 20, 1, F_THREADS | F_LONG, 10),
    t!("node --max-old-space-size=4096 /usr/local/bin/npm start", "@self", FAM_DEV, 620000, 82000, 30, 1, F_THREADS | F_LONG, 6),
    t!("npm install --no-audit --no-fund", "@self", FAM_DEV, 412000, 62000, 80, 1, F_THREADS | F_SHORT, 8),
    t!("npx next build", "@self", FAM_DEV, 612000, 92000, 180, 1, F_THREADS | F_SHORT, 4),
    t!("next build", "@self", FAM_DEV, 612000, 92000, 180, 1, F_THREADS | F_SHORT, 4),
    t!("python3 -m gunicorn app:app -b 0.0.0.0:8000 -w 4", "www-data", FAM_WEB, 204000, 42000, 20, 1, F_THREADS | F_LONG, 6),
    t!("python3 manage.py runserver 0.0.0.0:8000", "@self", FAM_DEV, 154000, 36000, 10, 1, F_THREADS | F_LONG, 5),
    t!("python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000", "@self", FAM_DEV, 184000, 41000, 10, 1, F_THREADS | F_LONG, 5),
    t!("java -Xmx2g -XX:+UseG1GC -jar /opt/app/app.jar --spring.profiles.active=prod", "app", FAM_WEB, 3140000, 820000, 40, 1, F_THREADS | F_LONG, 6),
    t!("go build -o /app/server ./cmd/server", "@self", FAM_DEV, 820000, 154000, 850, 1, F_BUSY, 5),
    t!("webpack --mode production", "@self", FAM_DEV, 712000, 122000, 350, 1, F_THREADS | F_SHORT, 4),
    t!("vite build --outDir dist", "@self", FAM_DEV, 612000, 102000, 280, 1, F_THREADS | F_SHORT, 4),
    t!("tsc --noEmit --project tsconfig.json", "@self", FAM_DEV, 512000, 92000, 220, 1, F_THREADS | F_SHORT, 4),
    t!("eslint src --ext .ts,.tsx", "@self", FAM_DEV, 412000, 72000, 180, 1, F_THREADS | F_SHORT, 4),
    t!("jest --watch --runInBand", "@self", FAM_DEV, 512000, 92000, 120, 1, F_THREADS | F_LONG, 3),
    t!("docker build -t app:latest .", "root", FAM_DEV, 204000, 32000, 4, 1, F_THREADS | F_SHORT, 5),
    t!("docker compose up --remove-orphans", "root", FAM_DEV, 204000, 32000, 2, 1, F_THREADS | F_LONG, 4),
    t!("ansible-playbook -i inventory/hosts site.yml", "@self", FAM_DEV, 104000, 32000, 3, 1, F_THREADS | F_SHORT, 3),
    t!("terraform apply -auto-approve", "@self", FAM_DEV, 124000, 36000, 2, 1, F_THREADS | F_SHORT, 3),
    t!("pip install -r requirements.txt", "@self", FAM_DEV, 154000, 32000, 6, 1, F_THREADS | F_SHORT, 4),
    t!("composer install --no-dev --optimize-autoloader", "@self", FAM_DEV, 104000, 26000, 4, 1, F_THREADS | F_SHORT, 3),
    t!("uv sync --frozen", "@self", FAM_DEV, 124000, 31000, 5, 1, F_THREADS | F_SHORT, 3),
    t!("julia --threads auto --project .", "@self", FAM_DEV, 412000, 122000, 20, 1, F_THREADS | F_LONG, 2),
    t!("cmake --build build --parallel 8", "@self", FAM_DEV, 82000, 21000, 400, 1, F_SHORT, 4),
    t!("ninja -C build", "@self", FAM_DEV, 52000, 15400, 350, 1, F_SHORT, 3),
    t!("clang -c src/main.c -O3 -o src/main.o", "@self", FAM_DEV, 124000, 26000, 900, 1, F_BUSY, 4),
    t!("ld -o app main.o util.o -lc", "@self", FAM_DEV, 62000, 15400, 300, 1, F_BUSY, 3),
    t!("mkinitcpio -k /boot/vmlinuz-linux -c /etc/mkinitcpio.conf -g /boot/initramfs-linux.img", "root", FAM_DEV, 42000, 10400, 250, 1, F_SHORT, 2),

    // ---- monitoring and logging --------------------------------------------
    t!("/usr/bin/prometheus-node-exporter", "prometheus", FAM_MON, 1612928, 19184, 1, 1, F_SESSION | F_THREADS, 10),
    t!("/usr/bin/prometheus --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/var/lib/prometheus", "prometheus", FAM_MON, 1540000, 208000, 6, 1, F_SESSION | F_THREADS, 6),
    t!("/usr/sbin/grafana-server --config=/etc/grafana/grafana.ini --pidfile=/run/grafana/grafana-server.pid", "grafana", FAM_MON, 820000, 124000, 3, 1, F_SESSION | F_THREADS, 5),
    t!("/usr/bin/telegraf --config /etc/telegraf/telegraf.conf", "telegraf", FAM_MON, 204000, 42000, 2, 1, F_THREADS, 4),
    t!("/usr/bin/filebeat -e -c /etc/filebeat/filebeat.yml", "root", FAM_MON, 312000, 52000, 4, 1, F_THREADS, 4),
    t!("/usr/bin/metricbeat -e -c /etc/metricbeat/metricbeat.yml", "root", FAM_MON, 304000, 51000, 3, 1, F_THREADS, 3),
    t!("/usr/bin/fluent-bit -c /etc/fluent-bit/fluent-bit.conf", "root", FAM_MON, 104000, 21000, 2, 1, F_THREADS, 4),
    t!("/usr/bin/vector --config /etc/vector/vector.toml", "root", FAM_MON, 124000, 26000, 3, 1, F_THREADS, 3),
    t!("/usr/sbin/collectd", "root", FAM_MON, 82000, 21000, 1, 1, F_THREADS, 3),
    t!("/usr/sbin/snmpd -f -Lo", "root", FAM_MON, 32000, 8400, 0, 1, F_SESSION, 4),
    t!("/usr/sbin/zabbix_agentd -f", "zabbix", FAM_MON, 42000, 10400, 0, 1, F_SESSION, 3),
    t!("/usr/bin/datadog-agent run", "dd-agent", FAM_MON, 920000, 154000, 5, 1, F_SESSION | F_THREADS, 3),
    t!("/usr/bin/newrelic-infra --config /etc/newrelic-infra.yml", "root", FAM_MON, 204000, 42000, 2, 1, F_SESSION | F_THREADS, 2),
    t!("journalctl -f", "root", FAM_MON, 22000, 6200, 0, 1, F_LONG, 5),
    t!("tail -f /var/log/nginx/access.log", "root", FAM_MON, 8200, 3200, 0, 1, F_LONG, 6),
    t!("tail -f /var/log/syslog", "root", FAM_MON, 8200, 3200, 0, 1, F_LONG, 4),

    // ---- storage -----------------------------------------------------------
    t!("/usr/bin/ceph-osd -f --cluster ceph --id 0 --setuser ceph --setgroup ceph", "ceph", FAM_STO, 1540000, 308000, 5, 1, F_SESSION | F_THREADS, 3),
    t!("/usr/bin/ceph-mon -f --cluster ceph --id node1 --setuser ceph --setgroup ceph", "ceph", FAM_STO, 512000, 104000, 2, 1, F_SESSION | F_THREADS, 2),
    t!("/usr/sbin/glusterd --log-file=/var/log/glusterfs/glusterd.log", "root", FAM_STO, 204000, 52000, 1, 1, F_SESSION, 2),
    t!("/usr/sbin/smbd -F --no-process-group", "root", FAM_STO, 154000, 36000, 0, 1, F_SESSION, 4),
    t!("/usr/sbin/nmbd -F --no-process-group", "root", FAM_STO, 102000, 21000, 0, 1, F_SESSION, 3),
    t!("/usr/sbin/rpcbind -w -f", "rpc", FAM_STO, 10400, 3400, 0, 1, F_SESSION, 3),
    t!("/usr/bin/minio server /data --console-address :9001", "minio", FAM_STO, 512000, 82000, 3, 1, F_SESSION | F_THREADS, 3),
    t!("/usr/bin/rclone mount remote:/ /mnt/remote --allow-other", "root", FAM_STO, 204000, 42000, 1, 1, F_THREADS, 2),
    t!("/usr/bin/rsync --daemon --config=/etc/rsyncd.conf", "root", FAM_STO, 32000, 8400, 0, 1, F_SESSION, 3),

    // ---- mail --------------------------------------------------------------
    t!("/usr/lib/postfix/sbin/master -w", "root", FAM_MAIL, 20400, 6200, 0, 1, F_SESSION, 6),
    t!("qmgr -l -t unix -u", "postfix", FAM_MAIL, 15400, 5200, 0, 1, F_CHILD, 4),
    t!("pickup -l -t unix -u", "postfix", FAM_MAIL, 15400, 5200, 0, 1, F_CHILD, 4),
    t!("tlsmgr -l -t unix -u -c", "postfix", FAM_MAIL, 15400, 5200, 0, 1, F_CHILD, 3),
    t!("/usr/sbin/exim4 -bdf -q30m", "Debian-exim", FAM_MAIL, 40376, 24332, 1, 1, F_SESSION, 5),
    t!("/usr/sbin/dovecot -F", "root", FAM_MAIL, 32000, 8400, 0, 1, F_SESSION, 3),
    t!("dovecot/anvil", "dovecot", FAM_MAIL, 15400, 5200, 0, 1, F_CHILD, 2),
    t!("dovecot/auth -w", "dovecot", FAM_MAIL, 15400, 5200, 0, 1, F_CHILD, 2),

    // ---- desktop -----------------------------------------------------------
    t!("/usr/lib/xorg/Xorg :0 -seat seat0 -auth /run/lightdm/root/:0 -nolisten tcp vt7 -novtswitch", "root", FAM_DESK, 204000, 62000, 3, 1, F_SESSION | F_THREADS | F_TTY, 4),
    t!("/usr/bin/gnome-shell --mode=user", "@self", FAM_DESK, 1240000, 308000, 8, 1, F_SESSION | F_THREADS, 4),
    t!("/usr/libexec/gnome-terminal-server", "@self", FAM_DESK, 312000, 62000, 1, 1, F_THREADS, 3),
    t!("/usr/bin/pipewire", "@self", FAM_DESK, 104000, 21000, 1, 1, F_THREADS, 3),
    t!("/usr/bin/pipewire-pulse", "@self", FAM_DESK, 82000, 15400, 0, 1, F_THREADS, 3),
    t!("/usr/bin/wireplumber", "@self", FAM_DESK, 62000, 15400, 0, 1, F_THREADS, 2),
    t!("/usr/libexec/tracker-miner-fs-3", "@self", FAM_DESK, 204000, 42000, 0, 1, F_THREADS, 2),
    t!("/usr/libexec/evolution-data-server/evolution-alarm-notify", "@self", FAM_DESK, 204000, 42000, 0, 1, F_THREADS, 2),
    t!("/usr/share/code/code --type=renderer --crashpad-handler-pid={pid} --enable-crash-reporter= --no-sandbox", "@self", FAM_DESK, 1040000, 204000, 4, 2, F_THREADS, 3),
    t!("/usr/lib/firefox/firefox -contentproc -childID {n} -isForBrowser -prefsLen {n2} -parentBuildID 20240101 /usr/lib/firefox/firefox", "@self", FAM_DESK, 1240000, 308000, 5, 2, F_THREADS, 3),
    t!("/usr/bin/chromium --type=renderer --field-trial-handle={n2} --lang=en-US", "@self", FAM_DESK, 820000, 204000, 4, 2, F_THREADS, 2),
    t!("/usr/libexec/gsd-power", "@self", FAM_DESK, 62000, 15400, 0, 1, F_THREADS, 2),
    t!("/usr/libexec/gsd-color", "@self", FAM_DESK, 62000, 15400, 0, 1, F_THREADS, 2),
    t!("/usr/bin/nautilus --gapplication-service", "@self", FAM_DESK, 312000, 62000, 0, 1, F_THREADS, 2),
    t!("/usr/libexec/ibus-daemon -drxR", "@self", FAM_DESK, 82000, 21000, 0, 1, F_THREADS, 2),
    t!("/usr/bin/gnome-keyring-daemon --daemonize --login", "@self", FAM_DESK, 82000, 21000, 0, 1, F_THREADS, 2),
    t!("/usr/bin/vim /etc/nginx/nginx.conf", "@self", FAM_DESK, 22400, 8400, 0, 1, F_TTY, 3),
    t!("/usr/bin/bash", "@self", FAM_DESK, 7480, 3536, 0, 1, F_SESSION | F_TTY | F_LONG, 5),

    // ---- network -----------------------------------------------------------
    t!("/usr/sbin/NetworkManager --no-daemon", "root", FAM_NET, 154000, 32000, 1, 1, F_SESSION | F_THREADS, 5),
    t!("/sbin/dhclient -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases eth0", "root", FAM_NET, 12400, 4200, 0, 1, F_SESSION, 4),
    t!("/usr/sbin/wpa_supplicant -u -s -O /run/wpa_supplicant", "root", FAM_NET, 42000, 10400, 0, 1, F_SESSION, 3),
    t!("/usr/sbin/openvpn --config /etc/openvpn/server.conf", "root", FAM_NET, 32000, 8400, 0, 1, F_SESSION, 3),
    t!("/usr/bin/wireguard-go wg0", "root", FAM_NET, 42000, 10400, 0, 1, F_THREADS, 3),
    t!("/usr/sbin/keepalived -D", "root", FAM_NET, 20400, 6200, 0, 1, F_SESSION, 3),
    t!("/usr/sbin/dnsmasq --no-daemon", "dnsmasq", FAM_NET, 15400, 5200, 0, 1, F_SESSION, 4),
    t!("/usr/sbin/unbound -d -p", "unbound", FAM_NET, 62000, 15400, 0, 1, F_SESSION, 3),
    t!("/usr/sbin/ntpd -g -u ntp:ntp", "ntp", FAM_NET, 20400, 6200, 0, 1, F_SESSION, 3),
    t!("/usr/bin/ssh -N -L 8080:127.0.0.1:80 deploy@10.0.0.5", "@self", FAM_NET, 15400, 5200, 0, 1, F_LONG, 4),
    t!("/usr/bin/ssh deploy@10.0.0.5", "@self", FAM_NET, 15400, 5200, 0, 1, F_TTY, 4),
    t!("/usr/bin/scp -r dist/ deploy@10.0.0.5:/var/www/app", "@self", FAM_NET, 20400, 6200, 2, 1, F_SHORT, 3),
    t!("/usr/bin/curl -fsSL https://example.com/releases/app.tar.gz -o /tmp/app.tar.gz", "@self", FAM_NET, 15400, 5200, 1, 1, F_SHORT, 4),
    t!("/usr/bin/wget --quiet --show-progress https://example.com/releases/app.tar.gz", "@self", FAM_NET, 20400, 6200, 1, 1, F_SHORT, 4),
    t!("/usr/bin/wget -i downloads.txt", "@self", FAM_NET, 20400, 6200, 1, 1, F_SHORT, 2),
];

pub fn family_id(name: &[u8]) -> Option<u8> {
    match name {
        b"sys" | b"system" => Some(FAM_SYS),
        b"web" => Some(FAM_WEB),
        b"db" | b"database" => Some(FAM_DB),
        b"ctr" | b"container" | b"containers" => Some(FAM_CTR),
        b"dev" | b"build" => Some(FAM_DEV),
        b"mon" | b"monitor" | b"monitoring" => Some(FAM_MON),
        b"sto" | b"storage" => Some(FAM_STO),
        b"mail" => Some(FAM_MAIL),
        b"desk" | b"desktop" => Some(FAM_DESK),
        b"net" | b"network" => Some(FAM_NET),
        _ => None,
    }
}

pub fn family_name(id: u8) -> &'static str {
    match id {
        FAM_SYS => "sys",
        FAM_WEB => "web",
        FAM_DB => "db",
        FAM_CTR => "ctr",
        FAM_DEV => "dev",
        FAM_MON => "mon",
        FAM_STO => "sto",
        FAM_MAIL => "mail",
        FAM_DESK => "desk",
        FAM_NET => "net",
        _ => "?",
    }
}

/// Family weights for the three realistic machine roles. A server has no
/// desktop session, a desktop has little web or database infrastructure, and
/// a dev machine is weighted toward build tools.
pub fn profile_weights(profile: &[u8]) -> [u16; 10] {
    if profile == b"desktop" {
        //        sys web  db ctr dev mon sto mail desk net
        [22, 2, 3, 4, 10, 3, 3, 0, 40, 13]
    } else if profile == b"dev" {
        [18, 5, 6, 10, 34, 6, 4, 0, 12, 5]
    } else {
        // server
        [22, 14, 12, 10, 8, 8, 6, 4, 0, 6]
    }
}
