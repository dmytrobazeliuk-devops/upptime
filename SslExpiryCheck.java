import org.yaml.snakeyaml.Yaml;
import java.io.*;
import java.net.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.net.ssl.*;

public class SslExpiryCheck {
    static final String SLACK_WEBHOOK = System.getenv("SLACK_WEBHOOK_URL");
    static final String CACHE_FILE = ".ssl_check_cache";
    static final int WARN_DAYS = 20;

    public static void main(String[] args) throws Exception {
        Map<String, String> cache = loadCache();
        InputStream input = new FileInputStream(".upptimerc.yml");
        Yaml yaml = new Yaml();
        Map<String, Object> data = yaml.load(input);

        List<Map<String, Object>> sites = (List<Map<String, Object>>) data.get("sites");
        if (sites == null) {
            System.out.println("No 'sites' in .upptimerc.yml");
            System.exit(0);
        }

        Map<String, String> newCache = new HashMap<>();

        for (Map<String, Object> site : sites) {
            String name = (String) site.get("name");
            String url = (String) site.get("url");

            if (url == null || !url.startsWith("https://")) {
                System.out.println("[SKIP] " + name + ": " + url + " (not https)");
                continue;
            }

            String prevStatus = cache.get(url);
            if ("down".equals(prevStatus)) {
                System.out.println("[CACHED-DOWN] " + name + ": " + url + " (skipped)");
                newCache.put(url, "down");
                continue;
            }

            URL u = new URL(url);
            String host = u.getHost();

            // DNS check
            boolean hasA = false;
            try {
                InetAddress[] addresses = InetAddress.getAllByName(host);
                hasA = addresses != null && addresses.length > 0;
            } catch (Exception ex) {
                // No A/AAAA record
            }
            if (!hasA) {
                System.out.println("[SKIP] " + name + ": " + url + " (no DNS record for " + host + ")");
                continue;
            }

            // Port 443 check
            if (!portOpen(host, 443, 3000)) {
                System.out.println("[SKIP] " + name + ": " + url + " (port 443 closed)");
                continue;
            }

            try {
                int days = checkSslExpiry(url);
                if (days < 0) {
                    String msg = "[ERROR] " + name + " (" + url + ") SSL expired!";
                    System.out.println(msg);
                    if (!"down".equals(prevStatus)) sendSlack(msg);
                    newCache.put(url, "down");
                } else if (days < WARN_DAYS) {
                    String msg = "[WARN] " + name + " (" + url + ") SSL expires in " + days + " days";
                    System.out.println(msg);
                    if (prevStatus == null || "ok".equals(prevStatus)) sendSlack(msg);
                    newCache.put(url, "warn:" + days);
                } else {
                    System.out.println("[OK] " + name + " (" + url + ") SSL expires in " + days + " days");
                    // Якщо повернувся до норми — інформувати
                    if (prevStatus != null && !"ok".equals(prevStatus)) {
                        String msg = "[INFO] " + name + " (" + url + ") SSL renewed/ok (" + days + " days)";
                        sendSlack(msg);
                    }
                    newCache.put(url, "ok");
                }
            } catch (Exception e) {
                String msg = "[FAIL] " + name + " (" + url + "): " + e.getMessage();
                System.out.println(msg);
                sendSlack(msg);
                newCache.put(url, "down");
            }
        }

        saveCache(newCache);
        System.exit(0); // Завжди успіх для GitHub Actions
    }

    public static void sendSlack(String message) {
        if (SLACK_WEBHOOK == null || SLACK_WEBHOOK.isEmpty()) return;
        try {
            String payload = "{\"text\":\"" + message.replace("\"", "\\\"") + "\"}";
            URL url = new URL(SLACK_WEBHOOK);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            try (OutputStream os = conn.getOutputStream()) {
                os.write(payload.getBytes("utf-8"));
            }
            int code = conn.getResponseCode();
        } catch (Exception e) {
            System.out.println("[Slack Error] " + e.getMessage());
        }
    }

    // Check if port is open (with timeout)
    private static boolean portOpen(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    // Return days until expiry, or -1 if expired (таймаут 5 сек)
    private static int checkSslExpiry(String urlStr) throws Exception {
        URL url = new URL(urlStr);
        String host = url.getHost();
        int port = url.getPort() == -1 ? 443 : url.getPort();

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, null, null);

        SSLSocketFactory factory = context.getSocketFactory();
        try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
            socket.setSoTimeout(5000);
            socket.startHandshake();

            Certificate[] certs = socket.getSession().getPeerCertificates();
            X509Certificate cert = (X509Certificate) certs[0];

            Date now = new Date();
            Date notAfter = cert.getNotAfter();

            long diff = notAfter.getTime() - now.getTime();
            int days = (int) (diff / (1000 * 60 * 60 * 24));
            return days;
        }
    }

    // --- CACHE UTILS ---
    private static Map<String, String> loadCache() {
        Map<String, String> cache = new HashMap<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(CACHE_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] arr = line.split(" ", 2);
                if (arr.length == 2) cache.put(arr[0], arr[1]);
            }
        } catch (IOException e) { /* ignore if cache does not exist */ }
        return cache;
    }

    private static void saveCache(Map<String, String> cache) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(CACHE_FILE))) {
            for (Map.Entry<String, String> entry : cache.entrySet()) {
                writer.write(entry.getKey() + " " + entry.getValue());
                writer.newLine();
            }
        } catch (IOException e) {
            System.out.println("[Cache Error] " + e.getMessage());
        }
    }
}
