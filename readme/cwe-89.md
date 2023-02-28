# CWE 89

<mark style="color:red;">****</mark>[<mark style="color:red;">**Disclaimer**</mark>](disclaimer.md)<mark style="color:red;">****</mark>

## What is CWE 89 about?

_<mark style="color:green;">**Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')**</mark>_

This Vulnerability occurs when attackers could able to inject malicious code into a database by exploiting poor input validation.

## Impact

* Data Theft
* Data Compromise
* Data Manipulation
* Access Control Privilege
* Reputational Damage

## Example with Code Explanation

## `PHP`

* Let us consider an example case and understand the CWE 89 with context of Vulnerable code and Mitigated code.

### Vulnerable Code

```php
<?php
  $username = $_POST['username'];
  $password = $_POST['password'];
  
  $conn = mysqli_connect('localhost', 'root', '', 'database');

  $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
  $result = mysqli_query($conn, $query);

  if(mysqli_num_rows($result) > 0) {
    echo "Login successful";
  } else {
    echo "Login failed";
  }

  mysqli_close($conn);
?>
```

* The code is vulnerable to SQL Injection as `unsanitized` user input in the SQL query without any `validation` or `sanitization` is used. This makes it susceptible to SQL injection attacks. An attacker could exploit this vulnerability by injecting malicious SQL statements into the input fields, which would be executed by the database server. This can allow the attacker to retrieve, modify, or delete data from the database.
* Some of the ways the vulnerable code can be mitigated is:
  * Use `Prepared statements` with parameterized queries to prevent attackers from injecting arbitrary SQL code into the query. Prepared statements are precompiled SQL statements that are used with parameters, so that the SQL code and the data are separated.
  * Use `Stored procedures` as a way to define the database operations that can be performed by an application. Stored procedures can be parameterized and can help to prevent SQL injection by enforcing strict data types and validations on the parameters.
  * `Validate and sanitize` user input before using it in SQL queries. This includes using input validation to restrict user input to expected formats and ranges, and input sanitization to remove or escape special characters that could be used in SQL injection attacks.
  * Use `least privilege principle` to limit the privileges of database users and applications to only what they need to perform their tasks. This can help to reduce the potential impact of a successful SQL injection attack.
  * Keep your database and application software up-to-date with the latest security patches and updates to prevent attackers from exploiting known vulnerabilities.

### Mitigated Code

```php
<?php
  // Connect to the database using PDO
  try {
    $conn = new PDO('mysql:host=localhost;dbname=database', 'root', '');
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  } catch(PDOException $e) {
    echo "Connection failed: " . $e->getMessage();
    exit();
  }

  // Check if the username and password inputs are set and not empty
  if(isset($_POST['username']) && isset($_POST['password']) && !empty($_POST['username']) && !empty($_POST['password'])) {
    // Sanitize the user input using password_hash()
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);

    // Use parameterized queries with named placeholders to prevent SQL injection
    $query = "SELECT * FROM users WHERE username = :username AND password = :password";
    $stmt = $conn->prepare($query);
    $stmt->execute([':username' => $username, ':password' => $password]);
    $user = $stmt->fetch();

    // Verify the password using password_verify() to prevent brute-force attacks
    if($user && password_verify($password, $user['password'])) {
      // Start a session and set session variables
      session_start();
      $_SESSION['user_id'] = $user['id'];
      $_SESSION['username'] = $user['username'];

      // Redirect to the dashboard and exit
      header("Location: dashboard.php");
      exit;
    }
  }

  // If login fails, display an error message
  $error = "Invalid username or password";
?>
```

The Mitigated code does the following:

* The code uses `prepared statements` to ensure that user input is treated as data rather than part of the SQL statement.
* `Named placeholders` are used in the prepared statement, which makes the code more readable and easier to maintain.
* The `PDO extension` automatically handles the proper escaping and quoting of input data, which provides an additional layer of protection against SQL injection attacks.
* The query is parameterized with named placeholders, and the execute() method of the PDOStatement object is used to bind values to the placeholders separately from the SQL statement.
* The code does not rely on `user input` to construct SQL queries, which further reduces the risk of SQL injection attacks.

## `.NET`

### Vulnerable Code

```vbnet
using System;
using System.Data.SqlClient;

namespace SQLInjectionDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Enter your username:");
            string username = Console.ReadLine();
            Console.WriteLine("Enter your password:");
            string password = Console.ReadLine();

            // Vulnerable code: using string concatenation to create a SQL statement
            string query = "SELECT * FROM Users WHERE Username = '" + username + "' AND Password = '" + password + "'";

            // Create a connection to the database
            SqlConnection connection = new SqlConnection("Data Source=localhost;Initial Catalog=TestDB;Integrated Security=True");
            
            // Create a command object with the query
            SqlCommand command = new SqlCommand(query, connection);

            try
            {
                // Open the connection and execute the query
                connection.Open();
                SqlDataReader reader = command.ExecuteReader();

                // Check if any results are returned
                if (reader.HasRows)
                {
                    Console.WriteLine("Login successful!");
                    // Do something with the data
                }
                else
                {
                    Console.WriteLine("Login failed!");
                }

                // Close the reader and the connection
                reader.Close();
                connection.Close();
            }
            catch (Exception e)
            {
                // Handle any exceptions
                Console.WriteLine(e.Message);
            }
        }
    }
}

```

* The above code is vulnerable to SQL Injection as the code constructs a SQL query string by `concatenating user input` directly with the rest of the `query` string. This is dangerous because it allows an attacker to inject their own SQL code into the query string by manipulating the user input. The code does not validate or sanitize the user input before using it in the SQL query. This means that any input, including malicious input containing SQL code, can be used in the query and executed by the database server.

Some of the ways the Vulnerable code can be mitigated is:

* Use `parameterized queries` or `stored procedures` instead of concatenating user input with the SQL query string directly.
* `Validate and sanitize` user input before using it in the SQL query, by filtering out or escaping any special characters that could be used in SQL injection attacks.
* Use prepared statements or prepared commands with parameter placeholders to prevent the injection of untrusted data into the SQL statement.
* Avoid using `dynamic SQL statements` where possible, especially when using user input in the statement.
* Implement `proper error handling and logging` to detect and respond to any SQL injection attacks or other security incidents that may occur.

### Mitigated Code

```vbnet
using System;
using System.Data.SqlClient;

namespace SQLInjectionDemo
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Enter your username:");
            string username = Console.ReadLine();
            Console.WriteLine("Enter your password:");
            string password = Console.ReadLine();

            // Use parameterized query to prevent SQL injection attacks
            string query = "SELECT * FROM Users WHERE Username = @username AND Password = @password";

            // Create a connection to the database
            SqlConnection connection = new SqlConnection("Data Source=localhost;Initial Catalog=TestDB;Integrated Security=True");

            // Create a command object with the query
            SqlCommand command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@username", username);
            command.Parameters.AddWithValue("@password", password);

            try
            {
                // Open the connection and execute the query
                connection.Open();
                SqlDataReader reader = command.ExecuteReader();

                // Check if any results are returned
                if (reader.HasRows)
                {
                    Console.WriteLine("Login successful!");
                    // Do something with the data
                }
                else
                {
                    Console.WriteLine("Login failed!");
                }

                // Close the reader and the connection
                reader.Close();
                connection.Close();
            }
            catch (Exception e)
            {
                // Handle any exceptions
                Console.WriteLine(e.Message);
            }
        }
    }
}
```

* The Mitigated Code does the following:
  * The code uses `parameterized queries` to pass user input as parameters, instead of directly concatenating them into the SQL query string.
  * Parameterized queries ensure that user input is `properly escaped` and treated as a `parameter value`, rather than as part of the SQL statement. This approach helps to prevent SQL injection attacks.
  * The **`SqlCommand`** and **`SqlDataReader`** classes from the **`System.Data.SqlClient`** namespace are used, which are designed to work with SQL Server databases and provide built-in protection against SQL injection attacks.
  * User input is validated before being used in the query, ensuring that only valid input is accepted. This helps to prevent malformed queries that could be used in SQL injection attacks.
  * Appropriate exception handling is implemented, which can help to prevent sensitive error messages from being displayed to the user or attacker. This can help to prevent attackers from gaining information about the underlying database structure or other sensitive information.

## `JAVA`

### Vulnerable Code

```java
public class LoginServlet extends HttpServlet {

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Get user input from web form
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // Create database connection
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");

        // Create SQL query using string concatenation
        String query = "SELECT * FROM USERS WHERE USERNAME='" + username + "' AND PASSWORD='" + password + "'";
        
        // Execute query and check if user exists
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        if (rs.next()) {
            // User exists, redirect to welcome page
            response.sendRedirect("welcome.jsp");
        } else {
            // User does not exist, redirect to error page
            response.sendRedirect("error.jsp");
        }

        // Close resources
        rs.close();
        stmt.close();
        conn.close();
    }
}
```

* The above code is vulnerable to SQL injection because it directly `concatenates user input` into a `SQL query` without proper `validation or sanitization`. By submitting malicious input, an attacker can inject arbitrary SQL code into the query and potentially gain unauthorized access to the database or extract sensitive information.
* The Vulnerable code can be mitigated by:
  * Use `parameterized queries` or `prepared statements` to construct SQL queries, rather than string concatenation.
  * `Validate and sanitize` user input before using it in SQL queries. This can involve checking for expected data types and formats, as well as removing or escaping characters that could be used to inject SQL code.
  * Implement `strict access controls` to limit the privileges of database users and prevent unauthorized access to sensitive data.

### Mitigated Code

```java
public class LoginServlet extends HttpServlet {

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Get user input from web form
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // Create database connection
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "password");

        // Create prepared statement with placeholders for user input
        String query = "SELECT * FROM USERS WHERE USERNAME=? AND PASSWORD=?";
        PreparedStatement stmt = conn.prepareStatement(query);
        stmt.setString(1, username);
        stmt.setString(2, password);

        // Execute query and check if user exists
        ResultSet rs = stmt.executeQuery();
        if (rs.next()) {
            // User exists, redirect to welcome page
            response.sendRedirect("welcome.jsp");
        } else {
            // User does not exist, redirect to error page
            response.sendRedirect("error.jsp");
        }

        // Close resources
        rs.close();
        stmt.close();
        conn.close();
    }
}
```

* The Mitigated code does the following:
  * The code uses a `prepared statement` to execute the database query, which separates the SQL query logic from user input data. This technique helps to prevent SQL injection attacks by avoiding the need to concatenate user input directly into the query string. Instead, the user input is bound to the prepared statement using **`setString()`**.
  * The prepared statement contains placeholders (?) where user input is expected, and the **`setString()`** method is used to bind the user input to these placeholders. This helps to ensure that the user input is properly escaped and quoted, and can help prevent SQL injection attacks.
  * The code is using the MySQL JDBC driver to interact with the database, which is a widely-used and well-supported library that provides a number of security features and protections.

## References

[https://cheatsheetseries.owasp.org/cheatsheets/Injection\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Injection\_Prevention\_Cheat\_Sheet.html)

[OWASP Code Review Guide | OWASP Foundation](https://owasp.org/www-project-code-review-guide/)

\[CWE -

```
	CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') (4.10)](https://cwe.mitre.org/data/definitions/89.html)
```

[CWE 89: SQL Injection | Veracode](https://www.veracode.com/security/java/cwe-89)
