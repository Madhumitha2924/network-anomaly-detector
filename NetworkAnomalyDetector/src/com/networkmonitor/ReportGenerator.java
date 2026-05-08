package com.networkmonitor;

import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * ReportGenerator — Produces a human-readable anomaly detection report.
 * Mirrors the kind of incident reports used in Nokia's NOC (Network Operations Center).
 */
public class ReportGenerator {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public void generateReport(List<NetworkPacket> allPackets,
                               List<NetworkPacket> anomalies,
                               AnomalyDetector detector,
                               String outputPath) throws IOException {

        StringBuilder sb = new StringBuilder();
        String line = "═".repeat(72);
        String dline = "─".repeat(72);

        sb.append(line).append("\n");
        sb.append("   NETWORK TRAFFIC ANOMALY DETECTION REPORT\n");
        sb.append("   Nokia Bell Labs — AIOps / Network Security Analysis\n");
        sb.append("   Generated: ").append(LocalDateTime.now().format(FMT)).append("\n");
        sb.append("   Author:    Madhumitha C | B.Tech AI & Data Science, Veltech University\n");
        sb.append(line).append("\n\n");

        // ---- Executive Summary ----
        sb.append("1. EXECUTIVE SUMMARY\n").append(dline).append("\n");
        int totalPackets = allPackets.size();
        int flagged = anomalies.size();
        double detectionRate = (double) flagged / totalPackets * 100;

        sb.append(String.format("   Total packets analyzed  : %,d%n", totalPackets));
        sb.append(String.format("   Anomalies detected      : %,d%n", flagged));
        sb.append(String.format("   Detection rate          : %.1f%%%n", detectionRate));
        sb.append(String.format("   Normal traffic          : %,d (%.1f%%)%n",
            totalPackets - flagged, 100 - detectionRate));
        sb.append(String.format("   Baseline mean bytes/pkt : %,.0f%n", detector.getMeanBytes()));
        sb.append(String.format("   Baseline mean packets   : %,.0f%n", detector.getMeanPackets()));
        sb.append("\n");

        // ---- Anomaly Breakdown by Type ----
        sb.append("2. ANOMALY BREAKDOWN BY TYPE\n").append(dline).append("\n");
        Map<NetworkPacket.AnomalyType, Long> byType = anomalies.stream()
            .collect(Collectors.groupingBy(NetworkPacket::getAnomalyType, Collectors.counting()));

        String[] order = {"DDOS","PORT_SCAN","BRUTE_FORCE","LARGE_TRANSFER","HIGH_FREQUENCY","SUSPICIOUS_PORT"};
        for (String typeName : order) {
            NetworkPacket.AnomalyType type;
            try { type = NetworkPacket.AnomalyType.valueOf(typeName); } catch (Exception e) { continue; }
            long count = byType.getOrDefault(type, 0L);
            if (count == 0) continue;
            double pct = (double) count / flagged * 100;
            String bar = "█".repeat((int)(pct / 5)) + "░".repeat(20 - (int)(pct / 5));
            sb.append(String.format("   %-20s %s %,3d (%.0f%%)%n", typeName, bar, count, pct));
        }
        sb.append("\n");

        // ---- Severity Distribution ----
        sb.append("3. SEVERITY DISTRIBUTION\n").append(dline).append("\n");
        long critical = anomalies.stream().filter(p -> p.getAnomalyScore() >= 0.85).count();
        long high     = anomalies.stream().filter(p -> p.getAnomalyScore() >= 0.70 && p.getAnomalyScore() < 0.85).count();
        long medium   = anomalies.stream().filter(p -> p.getAnomalyScore() >= 0.50 && p.getAnomalyScore() < 0.70).count();
        sb.append(String.format("   [CRITICAL] score ≥ 0.85 : %,d packets%n", critical));
        sb.append(String.format("   [HIGH]     score ≥ 0.70 : %,d packets%n", high));
        sb.append(String.format("   [MEDIUM]   score ≥ 0.50 : %,d packets%n", medium));
        sb.append("\n");

        // ---- Top Suspicious Source IPs ----
        sb.append("4. TOP SUSPICIOUS SOURCE IPs\n").append(dline).append("\n");
        Map<String, Long> ipCounts = anomalies.stream()
            .collect(Collectors.groupingBy(NetworkPacket::getSourceIP, Collectors.counting()));
        ipCounts.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(10)
            .forEach(e -> {
                double avgScore = anomalies.stream()
                    .filter(p -> p.getSourceIP().equals(e.getKey()))
                    .mapToDouble(NetworkPacket::getAnomalyScore)
                    .average().orElse(0);
                sb.append(String.format("   %-20s  %,3d events  avg_score=%.2f%n",
                    e.getKey(), e.getValue(), avgScore));
            });
        sb.append("\n");

        // ---- Port Scan Analysis ----
        sb.append("5. PORT SCAN ANALYSIS\n").append(dline).append("\n");
        Map<String, Set<Integer>> portMap = detector.getPortsBySourceIP();
        portMap.entrySet().stream()
            .filter(e -> e.getValue().size() >= 5)
            .sorted((a, b) -> Integer.compare(b.getValue().size(), a.getValue().size()))
            .limit(8)
            .forEach(e -> sb.append(String.format(
                "   %-20s scanned %,d unique ports  [RISK: %s]%n",
                e.getKey(), e.getValue().size(),
                e.getValue().size() >= 10 ? "HIGH" : "MEDIUM")));
        sb.append("\n");

        // ---- Top 20 Anomalous Packets (Detail) ----
        sb.append("6. TOP 20 ANOMALOUS PACKETS (by score)\n").append(dline).append("\n");
        sb.append(String.format("   %-12s %-16s %-6s %-14s %-10s %-5s%n",
            "Packet ID", "Source IP", "DPort", "Type", "Score", "Bytes(KB)"));
        sb.append("   " + "─".repeat(68)).append("\n");

        anomalies.stream()
            .sorted(Comparator.comparingDouble(NetworkPacket::getAnomalyScore).reversed())
            .limit(20)
            .forEach(p -> sb.append(String.format(
                "   %-12s %-16s %-6d %-14s %-5.2f  %,8.1f KB%n",
                p.getPacketId(), p.getSourceIP(), p.getDestinationPort(),
                p.getAnomalyType(), p.getAnomalyScore(), p.getBytesSent() / 1024.0)));
        sb.append("\n");

        // ---- Algorithm Description ----
        sb.append("7. DETECTION METHODOLOGY\n").append(dline).append("\n");
        sb.append("   Algorithm 1 : Z-Score Detection\n");
        sb.append("                 Flags packets where |x - μ| / σ > 2.5 (bytes, packet count)\n");
        sb.append("   Algorithm 2 : IQR Outlier Detection\n");
        sb.append("                 Flags bytes > Q3 + 2.0 × IQR (robust to skewed distributions)\n");
        sb.append("   Algorithm 3 : Rule-Based Heuristics\n");
        sb.append("                 DDoS (>5000 pkts), HighFreq (>50 pkt/ms), BruteForce, BadPort\n");
        sb.append("   Algorithm 4 : IP Frequency Analysis\n");
        sb.append("                 Port scan detection: unique dest ports per source IP ≥ 10\n");
        sb.append("\n");

        // ---- Recommendations ----
        sb.append("8. RECOMMENDATIONS\n").append(dline).append("\n");
        if (byType.containsKey(NetworkPacket.AnomalyType.DDOS))
            sb.append("   [DDoS]         → Enable rate limiting and traffic scrubbing on affected endpoints\n");
        if (byType.containsKey(NetworkPacket.AnomalyType.PORT_SCAN))
            sb.append("   [Port Scan]    → Block scanning IPs at firewall; enable IDS signatures\n");
        if (byType.containsKey(NetworkPacket.AnomalyType.BRUTE_FORCE))
            sb.append("   [Brute Force]  → Enforce MFA, account lockout policy, and SSH key auth\n");
        if (byType.containsKey(NetworkPacket.AnomalyType.LARGE_TRANSFER))
            sb.append("   [Data Exfil]   → Inspect large HTTPS transfers; enable DLP policies\n");
        if (byType.containsKey(NetworkPacket.AnomalyType.SUSPICIOUS_PORT))
            sb.append("   [Susp. Ports]  → Block C2 ports (4444, 31337, 6666) at perimeter firewall\n");
        sb.append("\n");

        sb.append(line).append("\n");
        sb.append("   END OF REPORT | Nokia Bell Labs AIOps Project | Madhumitha C\n");
        sb.append(line).append("\n");

        // Write to file and also print to console
        String report = sb.toString();
        System.out.println(report);
        try (PrintWriter pw = new PrintWriter(new FileWriter(outputPath))) {
            pw.print(report);
        }
        System.out.println("[Report saved to: " + outputPath + "]");
    }
}
