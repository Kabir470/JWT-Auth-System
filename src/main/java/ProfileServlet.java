import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import java.io.IOException;

@WebServlet("/api/profile")
public class ProfileServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {

        // authFilter already verified the token,, put the username here
        String username = (String) req.getAttribute("username");

        resp.setContentType("application/json");
        resp.setStatus(200);
        resp.getWriter().write("{\"message\":\"Hello " + username + "\",\"status\":\"authenticated\"}");
    }
}