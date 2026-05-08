package com.networkmonitor;

import java.time.LocalDateTime;
import java.util.*;

/**
 * TrafficGenerator — Simulates realistic network packet/flow data.
 *
 * Generates two datasets:
 *   baseline  — normal traffic used to train the detector
 *   live      — mixed normal + injected anomalies used to test detection
 *
 * Anomaly types injected:
 *   PORT_SCAN      — one IP hits many different ports rapidly
 *   DDOS           — massive packet count from single IP
 *   LARGE_TRANSFER — huge byte payload (data exfiltration style)
 *   HIGH_FREQUENCY — very high packets-per-ms rate
 *   BRUTE_FORCE    — repeated hits on SSH (port 22)
 *   SUSPICIOUS_PORT— traffic to known bad ports
 */
public class TrafficGenerator {

    private final Random rng;

    // Typical office/server subnet ranges
    private static final String[] INTERNAL_IPS = {
        "192.168.1.", "192.168.2.", "10.0.0.", "10.10.1.", "172.16.0."
    };
    private static final String[] EXTERNAL_IPS = {
        "203.0.113.", "198.51.100.", "185.220.101.", "91.108.4.",
        "104.21.34.", "172.67.182.", "8.8.", "1.1."
    };
    private static final int[] COMMON_PORTS = {80, 443, 53, 25, 110, 143, 8080, 8443, 3000, 5432};
    private static final NetworkPacket.Protocol[] PROTOCOLS = NetworkPacket.Protocol.values();

    public TrafficGenerator(long seed) {
        this.rng = new Random(seed);
    }

    /** Generate normal baseline traffic (no anomalies). */
    public List<NetworkPacket> generateBaseline(int count) {
        List<NetworkPacket> packets = new ArrayList<>();
        LocalDateTime base = LocalDateTime.now().minusHours(2);
        for (int i = 0; i < count; i++) {
            packets.add(normalPacket("BASE-" + i, base.plusSeconds(i * 2)));
        }
        return packets;
    }

    /** Generate live traffic with injected anomalies. */
    public List<NetworkPacket> generateLiveTraffic(int normalCount, int anomalyCount) {
        List<NetworkPacket> packets = new ArrayList<>();
        LocalDateTime base = LocalDateTime.now().minusMinutes(30);

        // Normal packets
        for (int i = 0; i < normalCount; i++) {
            packets.add(normalPacket("PKT-" + i, base.plusSeconds(i)));
        }

        // Inject anomalies at random positions
        String scannerIP  = "185.220.101." + (10 + rng.nextInt(50));
        String ddosIP     = "91.108.4."    + (10 + rng.nextInt(50));
        String bruteForcIP= "203.0.113."   + (10 + rng.nextInt(50));

        for (int i = 0; i < anomalyCount; i++) {
            int type = i % 6;
            LocalDateTime ts = base.plusSeconds(normalCount + i * 3);
            NetworkPacket anomaly;
            switch (type) {
                case 0 -> anomaly = injectPortScan(scannerIP, "10.0.0." + (rng.nextInt(50)+1), i, ts);
                case 1 -> anomaly = injectDDoS(ddosIP, "10.10.1." + (rng.nextInt(20)+1), i, ts);
                case 2 -> anomaly = injectLargeTransfer(i, ts);
                case 3 -> anomaly = injectHighFrequency(i, ts);
                case 4 -> anomaly = injectBruteForce(bruteForcIP, "192.168.1." + (rng.nextInt(20)+100), i, ts);
                default -> anomaly = injectSuspiciousPort(i, ts);
            }
            packets.add(anomaly);
        }

        // Shuffle so anomalies aren't all at the end
        Collections.shuffle(packets, rng);
        return packets;
    }

    // ---- Normal packet factory ----
    private NetworkPacket normalPacket(String id, LocalDateTime ts) {
        String srcSubnet = INTERNAL_IPS[rng.nextInt(INTERNAL_IPS.length)];
        String dstSubnet = rng.nextBoolean() ? EXTERNAL_IPS[rng.nextInt(EXTERNAL_IPS.length)] : INTERNAL_IPS[rng.nextInt(INTERNAL_IPS.length)];
        String srcIP = srcSubnet + (rng.nextInt(200) + 10);
        String dstIP = dstSubnet + (rng.nextInt(200) + 10);
        int dstPort  = COMMON_PORTS[rng.nextInt(COMMON_PORTS.length)];
        int srcPort  = 1024 + rng.nextInt(60000);
        NetworkPacket.Protocol proto = rng.nextInt(10) < 6 ? NetworkPacket.Protocol.TCP : NetworkPacket.Protocol.UDP;
        long bytes   = 500 + (long)(rng.nextGaussian() * 1500 + 3000);   // ~3KB avg
        long pkts    = 1  + (long)(Math.abs(rng.nextGaussian()) * 20 + 15);
        double dur   = 10 + rng.nextDouble() * 500;
        bytes = Math.max(100, bytes);
        pkts  = Math.max(1, pkts);
        return new NetworkPacket(id, srcIP, dstIP, srcPort, dstPort, proto, bytes, pkts, dur, ts);
    }

    // ---- Anomaly injectors ----
    private NetworkPacket injectPortScan(String srcIP, String dstIP, int i, LocalDateTime ts) {
        // Low bytes, many different ports (simulated by using high random port)
        int suspPort = 1 + rng.nextInt(65534);
        return new NetworkPacket("SCAN-" + i, srcIP, dstIP, rng.nextInt(60000)+1024,
            suspPort, NetworkPacket.Protocol.TCP,
            64, 1, 0.5, ts);
    }

    private NetworkPacket injectDDoS(String srcIP, String dstIP, int i, LocalDateTime ts) {
        // Massive packet count, UDP flood
        long pkts  = 8000 + rng.nextInt(20000);
        long bytes = pkts * 64;
        return new NetworkPacket("DDOS-" + i, srcIP, dstIP, rng.nextInt(60000)+1024,
            80, NetworkPacket.Protocol.UDP,
            bytes, pkts, 100.0, ts);
    }

    private NetworkPacket injectLargeTransfer(int i, LocalDateTime ts) {
        // Exfiltration-style: huge bytes over a long duration
        String srcIP = "192.168.1." + (rng.nextInt(50)+10);
        String dstIP = EXTERNAL_IPS[rng.nextInt(EXTERNAL_IPS.length)] + (rng.nextInt(200)+10);
        long bytes   = 500_000_000L + (long)(rng.nextDouble() * 500_000_000L); // 500MB–1GB
        long pkts    = bytes / 1500;
        return new NetworkPacket("EXFIL-" + i, srcIP, dstIP, rng.nextInt(60000)+1024,
            443, NetworkPacket.Protocol.TCP,
            bytes, pkts, 30000.0, ts);
    }

    private NetworkPacket injectHighFrequency(int i, LocalDateTime ts) {
        // Thousands of packets in a very short window
        long pkts  = 2000 + rng.nextInt(5000);
        long bytes = pkts * 200;
        String srcIP = EXTERNAL_IPS[rng.nextInt(EXTERNAL_IPS.length)] + (rng.nextInt(200)+10);
        return new NetworkPacket("HFREQ-" + i, srcIP, "10.0.0." + (rng.nextInt(50)+1),
            rng.nextInt(60000)+1024, 80, NetworkPacket.Protocol.TCP,
            bytes, pkts, 10.0, ts); // very short duration → high pps
    }

    private NetworkPacket injectBruteForce(String srcIP, String dstIP, int i, LocalDateTime ts) {
        // Many packets targeting SSH port 22
        long pkts  = 500 + rng.nextInt(1000);
        long bytes = pkts * 128;
        return new NetworkPacket("BRUTE-" + i, srcIP, dstIP, rng.nextInt(60000)+1024,
            22, NetworkPacket.Protocol.TCP,
            bytes, pkts, pkts * 2.0, ts);
    }

    private NetworkPacket injectSuspiciousPort(int i, LocalDateTime ts) {
        // Traffic to known malware/C2 ports
        int[] badPorts = {4444, 31337, 6666, 1337, 9999, 23};
        int port = badPorts[rng.nextInt(badPorts.length)];
        String srcIP = INTERNAL_IPS[rng.nextInt(INTERNAL_IPS.length)] + (rng.nextInt(50)+10);
        String dstIP = EXTERNAL_IPS[rng.nextInt(EXTERNAL_IPS.length)] + (rng.nextInt(200)+10);
        long bytes   = 1000 + rng.nextInt(50000);
        long pkts    = 5 + rng.nextInt(100);
        return new NetworkPacket("SUSPPORT-" + i, srcIP, dstIP, rng.nextInt(60000)+1024,
            port, NetworkPacket.Protocol.TCP,
            bytes, pkts, 200.0, ts);
    }
}
