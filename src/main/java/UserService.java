import java.util.HashMap;
import java.util.Map;

public class UserService {

    // username → password (plaintext for learning only, not for production)
    // in production: store BCrypt hashes, never plaintext
    private static final Map<String, String> USERS = new HashMap<>();

    static {
        USERS.put("alice", "pass123");
        USERS.put("bob", "hello");
    }

    public boolean isValid(String username, String password) {
        String stored = USERS.get(username);
        return stored != null && stored.equals(password);
    }
}