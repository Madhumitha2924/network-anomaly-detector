package com.networkmonitor;

import java.io.*;
import java.util.*;

/**
 * Main — Entry point for the Network Traffic Anomaly Detector.
 *
 * Pipeline:
 *   1. Generate baseline traffic (normal)  → fit the statistical detector
 *   2. Generate live traffic (normal + injected anomalies)
 *   3. Run detection algorithms (Z-score, IQR, rules, IP analysis)
 *   4. Print results + generate full report
 *
 * Nokia Bell Labs relevance:
 *   This mirrors Nokia's AIOps framework for autonomous network monitoring —
 *   statistical baselining + rule-based detection on live network telemetry.
 */
public class Main {

    public static void main(String[] args) throws Exception {

        System.out.println("╔══════════════════════════════════════════════════════════════════════╗");
        System.out.println("║     NETWORK TRAFFIC ANOMALY DETECTOR — Nokia Bell Labs AIOps         ║");
        System.out.println("║     Developer: Madhumitha C | B.Tech AI & DS, Veltech University     ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════╝");
        System.out.println();

        // ── Step 1: Generate Baseline (normal traffic) ──────────────────────
        System.out.println("[ Step 1 ] Generating baseline traffic dataset...");
        TrafficGenerator generator = new TrafficGenerator(42L);
        List<NetworkPacket> baseline = generator.generateBaseline(500);
        System.out.printf("           Generated %,d normal baseline packets%n%n", baseline.size());

        // ── Step 2: Train / Fit the Detector ────────────────────────────────
        System.out.println("[ Step 2 ] Fitting anomaly detector on baseline...");
        AnomalyDetector detector = new AnomalyDetector();
        detector.fit(baseline);
        System.out.println();

        // ── Step 3: Generate Live Traffic (normal + anomalies) ──────────────
        System.out.println("[ Step 3 ] Generating live network traffic (with injected anomalies)...");
        List<NetworkPacket> liveTraffic = generator.generateLiveTraffic(300, 60);
        System.out.printf("           Generated %,d packets (%d normal + 60 injected anomalies)%n%n",
            liveTraffic.size(), liveTraffic.size() - 60);

        // ── Step 4: Run Detection ────────────────────────────────────────────
        System.out.println("[ Step 4 ] Running anomaly detection algorithms...");
        long startMs = System.currentTimeMillis();
        List<NetworkPacket> anomalies = detector.detect(liveTraffic);
        long elapsedMs = System.currentTimeMillis() - startMs;
        System.out.printf("           Detection complete in %d ms%n", elapsedMs);
        System.out.printf("           Flagged: %,d / %,d packets (%.1f%%)%n%n",
            anomalies.size(), liveTraffic.size(),
            (double) anomalies.size() / liveTraffic.size() * 100);

        // ── Step 5: Print live alerts (top 15 by score) ─────────────────────
        System.out.println("[ Step 5 ] LIVE ANOMALY ALERTS (top 15 by severity):");
        System.out.println("─".repeat(72));
        anomalies.stream()
            .sorted(Comparator.comparingDouble(NetworkPacket::getAnomalyScore).reversed())
            .limit(15)
            .forEach(p -> {
                String severity = p.getAnomalyScore() >= 0.85 ? "CRITICAL" :
                                  p.getAnomalyScore() >= 0.70 ? "HIGH    " : "MEDIUM  ";
                System.out.printf("[%s] score=%.2f | %-14s | %s%n",
                    severity, p.getAnomalyScore(), p.getAnomalyType(), p);
            });
        System.out.println("─".repeat(72));
        System.out.println();

        // ── Step 6: Generate Full Report ────────────────────────────────────
        System.out.println("[ Step 6 ] Generating full analysis report...");
        System.out.println("═".repeat(72));
        ReportGenerator reporter = new ReportGenerator();
        reporter.generateReport(liveTraffic, anomalies, detector, "anomaly_report.txt");

        // ── Step 7: Performance Summary ─────────────────────────────────────
        System.out.println();
        System.out.println("[ Summary ] Throughput: " +
            String.format("%,.0f", (liveTraffic.size() / Math.max(1.0, elapsedMs)) * 1000) +
            " packets/second");
        System.out.println("[ Summary ] Project demonstrates:");
        System.out.println("            - Statistical ML (Z-score + IQR) in pure Java");
        System.out.println("            - Rule-based heuristic engine (Nokia AIOps pattern)");
        System.out.println("            - OOP design: NetworkPacket, AnomalyDetector, ReportGenerator");
        System.out.println("            - Real-time network traffic analysis pipeline");
        System.out.println("            - Relevant to Nokia Bell Labs 5G/AIOps network security");
    }
}
