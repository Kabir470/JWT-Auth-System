import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class JwtUtil {
    // JWT utility class for token generation and validation

    // real code from here
    private static final String SECRET_KEY = "your-secret-key";
    private static final long EXP_TIME = 30000; // 30 seconds

    public static String generateToken(String username) throws Exception {
        String header = encode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");

        long now = System.currentTimeMillis() / 1000;
        long exp = now + EXP_TIME / 1000;
        String payloadjson = "{\"sub\":\"" + username + "\",\"exp\":" + exp + "}";
        String payload = encode(payloadjson);

        String signature = sign(header + "." + payload);
        return header + "." + payload + "." + signature;

    }

    public static String verifyAndGetUsername(String token) throws Exception {

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new Exception("Invalid token");
        }

        String expectedSig = sign(parts[0] + "." + parts[1]);
        if (!safeEquals(expectedSig, parts[2])) {
            throw new Exception("signature mismatch, token tampered");
        }

        String payloadjson = new String(Base64.getUrlDecoder().decode(parts[1]));

        long exp = extractLong(payloadjson, "exp");
        if (System.currentTimeMillis() / 1000 > exp) {
            throw new Exception("Token expired");
        }

        return extractString(payloadjson, "sub");

    }

    // private helper methods for the above methods
    private static String encode(String text) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }

    private static String sign(String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    // constant-time compare.. prevents timing attacks
    // (attacker cant guess the signature one byte at a time by measuring response
    // speed)
    private static boolean safeEquals(String a, String b) {
        if (a.length() != b.length())
            return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++)
            diff |= a.charAt(i) ^ b.charAt(i);
        return diff == 0;
    }

    // minimal jsonn value extractor.. no library needed for learning
    private static String extractString(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search) + search.length();
        int end = json.indexOf("\"", start);
        return json.substring(start, end);
    }

    private static long extractLong(String json, String key) {
        String search = "\"" + key + "\":";
        int start = json.indexOf(search) + search.length();
        int end = json.indexOf("}", start);
        // handle comma-separated fields
        int comma = json.indexOf(",", start);
        if (comma != -1 && comma < end)
            end = comma;
        return Long.parseLong(json.substring(start, end).trim());
    }
}