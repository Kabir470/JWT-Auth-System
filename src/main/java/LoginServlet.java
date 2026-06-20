import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import java.io.*;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {

    private final UserService users = new UserService();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        // read the request body {"username":"alice","password":"pass123"}
        BufferedReader reader = req.getReader();
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null)
            sb.append(line);
        String body = sb.toString();

        String username = extract(body, "username");
        String password = extract(body, "password");

        resp.setContentType("application/json");

        if (username == null || password == null) {
            resp.setStatus(400);
            resp.getWriter().write("{\"error\":\"provide username and password\"}");
            return;
        }

        if (!users.isValid(username, password)) {
            resp.setStatus(401);
            resp.getWriter().write("{\"error\":\"wrong credentials\"}");
            return;
        }

        try {
            String token = JwtUtil.generateToken(username);
            resp.setStatus(200);
            resp.getWriter().write("{\"token\":\"" + token + "\"}");
        } catch (Exception e) {
            resp.setStatus(500);
            resp.getWriter().write("{\"error\":\"server error\"}");
        }
    }

    // quick json value puller — no library needed
    private String extract(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start == -1)
            return null;
        start += search.length();
        int end = json.indexOf("\"", start);
        return json.substring(start, end);
    }
}
