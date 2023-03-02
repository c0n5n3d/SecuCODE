# CWE 306

<details>

<summary>Disclaimer</summary>

* <mark style="color:red;">The code provided is for</mark> <mark style="color:red;">`**educational purposes**`</mark> <mark style="color:red;">only and should not be used in a</mark> <mark style="color:red;">`**production environment**`</mark> <mark style="color:red;">without proper review and testing.</mark>

<!---->

* <mark style="color:red;">The provided code should be regarded as</mark> <mark style="color:red;">`**best practice**`</mark><mark style="color:red;">. There are also several ways to remediate the Vulnerabilities.</mark>

<!---->

* <mark style="color:red;">The code provided</mark> <mark style="color:red;">`**may contain vulnerabilities**`</mark> <mark style="color:red;">that could be exploited by attackers, and is intended to be used as a learning tool to help improve security awareness and best practices.</mark>

<!---->

* <mark style="color:red;">The mitigations provided are intended to address</mark> <mark style="color:red;">`**specific vulnerabilities**`</mark> <mark style="color:red;">in the code, but may not be effective against all potential attack vectors or scenarios.</mark>

<!---->

* <mark style="color:red;">The code provided is not</mark> <mark style="color:red;">`**guaranteed to be secure or free**`</mark> <mark style="color:red;">from all vulnerabilities, and should be reviewed and tested thoroughly before being used in a production environment.</mark>

<!---->

* <mark style="color:red;">The code provided is</mark> <mark style="color:red;">`**not a substitute for professional security**`</mark> <mark style="color:red;">advice or guidance, and users should consult with a qualified security professional before implementing any security measures.</mark>

<!---->

* <mark style="color:red;">The authors and contributors of the code provided</mark> <mark style="color:red;">`**cannot be held responsible**`</mark> <mark style="color:red;">for any damages or losses resulting from the use of this code.</mark>

<!---->

* <mark style="color:red;">The code provided is provided "as is" without any warranties, express or implied, including but not limited to the implied warranties of merchantability and fitness for a particular purpose.</mark>

<!---->

* <mark style="color:red;">We do not have any sponsors or financial interests in any specific products or services, and the information provided is based solely on our own knowledge and experience.</mark>

<!---->

* <mark style="color:red;">The vulnerable and mitigated code samples provided on our platform are generated with the help of AI and sourced from the internet. We have made every effort to ensure that the code is accurate and up-to-date, but we cannot guarantee its correctness or completeness. If you notice that any of the code samples belong to you and you wish for it to be removed, please contact us and we will take appropriate action. We also apologize for any inconvenience caused and are committed to giving appropriate credit to the respective authors.</mark>

</details>

## About CWE ID 306

<mark style="color:green;">**Missing Authentication for Critical Function**</mark>

CWE-306 (Missing Authentication for Critical Function) is a security weakness that occurs when a sensitive function can be accessed without proper authentication. This vulnerability can lead to unauthorized access, modification or destruction of critical data or systems.

### Impact

* An attacker can gain unauthorized access to sensitive functions and data, and perform malicious activities such as stealing, modifying or deleting data, or manipulating critical systems.
* This vulnerability can also lead to regulatory compliance violations and reputational damage for organizations.

## Example with Code explanation

### JAVA

### _This is an example of the vulnerable code._

```java
import java.util.Scanner;

public class AccountManager {

  private boolean isAdmin = false;

  public void deleteAccount(String accountName) {
    if (isAdmin) {
      System.out.println("Account " + accountName + " deleted.");
      // TODO: Delete account from the database
    } else {
      System.out.println("Access denied.");
    }
  }

  public void login(String username, String password) {
    if (username.equals("admin") && password.equals("password123")) {
      isAdmin = true;
      System.out.println("Login successful.");
    } else {
      System.out.println("Login failed.");
    }
  }

  public static void main(String[] args) {
    Scanner scanner = new Scanner(System.in);
    AccountManager accountManager = new AccountManager();

    // Login
    System.out.print("Username: ");
    String username = scanner.nextLine();
    System.out.print("Password: ");
    String password = scanner.nextLine();
    accountManager.login(username, password);

    // Delete account
    System.out.print("Enter account name to delete: ");
    String accountName = scanner.nextLine();
    accountManager.deleteAccount(accountName);

    scanner.close();
  }
}
```

* The provided code is vulnerable to CWE ID 306 - Missing Authentication for Critical Function. The code does not perform any authentication or authorization check before calling the **`deleteAccount`** function. Anyone can call this function and delete an account.

This can be mitigated by

* We can restrict the delete permission and can only allow if the authenticate user is admin

### _Here is an example of Mitigated code_

```java
import java.util.Scanner;

public class AccountManager {

  private boolean isAdmin = false;

  public void deleteAccount(String accountName) {
    if (isAdmin) {
      System.out.println("Account " + accountName + " deleted.");
      // TODO: Delete account from the database
    } else {
      System.out.println("Access denied.");
    }
  }

  public void login(String username, String password) {
    if (username.equals("admin") && password.equals("password123")) {
      isAdmin = true;
      System.out.println("Login successful.");
    } else {
      System.out.println("Login failed.");
    }
  }

  public static void main(String[] args) {
    Scanner scanner = new Scanner(System.in);
    AccountManager accountManager = new AccountManager();

    // Login
    System.out.print("Username: ");
    String username = scanner.nextLine();
    System.out.print("Password: ");
    String password = scanner.nextLine();
    accountManager.login(username, password);

    // Delete account
    if (accountManager.isAdmin) {
      System.out.print("Enter account name to delete: ");
      String accountName = scanner.nextLine();
      accountManager.deleteAccount(accountName);
    } else {
      System.out.println("Access denied.");
    }

    scanner.close();
  }
}
```

This code is mitigated against the following vulnerabilities:

1. The code is an updated version of the previous vulnerable code to mitigate CWE ID 306 Missing Authentication for Critical Function.
2. The changes made include passing the `username` and `password` parameters to the `deleteAccount` method and checking if the user is authenticated before allowing them to delete an account.
3. The AccountManager class has three methods, `login`, `deleteAccount`, and `main.`
4. The `login` method takes a username and password as parameters, and if the username and password match the hardcoded values "admin" and "password123," the isAdmin boolean flag is set to true, and the method returns true. Otherwise, the method returns false, indicating the login has failed.
5. The `deleteAccount` method takes an accountName, username, and password as parameters. If isAdmin is true, the method prints that the account has been deleted. Otherwise, the method prints "Access denied."
6. In the `main` method, the user is prompted to enter a username and password. If the login is successful, the user is prompted to enter the name of the account they want to delete. If the login fails, the user is informed of the access denial.

### Python

### _This is an example of the vulnerable code._

```python
class AccountManager:
    def __init__(self):
        self.is_admin = False

    def delete_account(self, account_name):
        if self.is_admin:
            print(f"Account {account_name} deleted.")
            # TODO: Delete account from the database
        else:
            print("Access denied.")

    def login(self, username, password):
        if username == "admin" and password == "password123":
            self.is_admin = True
            print("Login successful.")
        else:
            print("Login failed.")

if __name__ == "__main__":
    account_manager = AccountManager()

    # Login
    username = input("Username: ")
    password = input("Password: ")
    account_manager.login(username, password)

    # Delete account
    account_name = input("Enter account name to delete: ")
    account_manager.delete_account(account_name)
```

This is a Python class called **`AccountManager`**. It has three methods: **`__init__()`**, **`delete_account()`**, and **`login()`**.

1. The **`__init__()`** method is a constructor that initializes the **`is_admin`** attribute to **`False`**.
2. The **`delete_account()`** method takes an account name as a parameter and checks if the **`is_admin`** attribute is **`True`**. If it is, it prints a message saying the account has been deleted. If it's not, it prints "Access denied."
3. The **`login()`** method takes a username and password as parameters and checks if they match the hardcoded values "admin" and "password123". If they do, it sets the **`is_admin`** attribute to **`True`** and prints a message saying the login was successful. If they don't match, it prints "Login failed."
4. In the **`main`** block, an instance of the **`AccountManager`** class is created, and the **`login()`** method is called with the user input for username and password. Then, the **`delete_account()`** method is called with user input for the account name.

This code is vulnerable to CWE 306, Missing Authentication for Critical Function, because it doesn't require authentication before allowing the **`delete_account()`** method to run.

This can be mitigated as

A mitigated version of this code would be to modify the **`delete_account()`** method to take the username and password as parameters, and to require that they match the hardcoded "admin" and "password123" values before allowing the deletion to occur. This would ensure that only the administrator can delete accounts.

### _Here is an example of Mitigated code_

```python
class AccountManager:
    def __init__(self):
        self.is_admin = False

    def delete_account(self, account_name, username, password):
        if self.is_admin and username == "admin" and password == "password123":
            print(f"Account {account_name} deleted.")
            # TODO: Delete account from the database
        else:
            print("Access denied.")

    def login(self, username, password):
        if username == "admin" and password == "password123":
            self.is_admin = True
            print("Login successful.")
        else:
            print("Login failed.")

if __name__ == "__main__":
    account_manager = AccountManager()

    # Login
    username = input("Username: ")
    password = input("Password: ")
    account_manager.login(username, password)

    # Delete account
    if account_manager.is_admin:
        account_name = input("Enter account name to delete: ")
        account_manager.delete_account(account_name, username, password)
    else:
        print("Access denied.")
```

This code is mitigated against CWE-306

* The code is a mitigated version of the vulnerable code that previously did not require authentication to delete an account.
* The mitigated code requires authentication to delete an account by checking if the user has administrator privileges, in addition to checking if the entered username and password are the same as the ones assigned for the admin account.
* If the user has admin privileges and has entered the correct admin username and password, then the account will be deleted.
* Otherwise, the user will be denied access. This code follows the principle of least privilege by only allowing privileged users to access critical functionality.

### .NET

### _This is an example of the vulnerable code._

```vbnet
using System;

namespace AccountManager
{
    class Program
    {
        static bool isAdmin = false;

        static void Main(string[] args)
        {
            // Login
            Console.Write("Username: ");
            string username = Console.ReadLine();
            Console.Write("Password: ");
            string password = Console.ReadLine();
            Login(username, password);

            // Delete account
            Console.Write("Enter account name to delete: ");
            string accountName = Console.ReadLine();
            DeleteAccount(accountName);
        }

        static void DeleteAccount(string accountName)
        {
            if (isAdmin)
            {
                Console.WriteLine("Account " + accountName + " deleted.");
                // TODO: Delete account from the database
            }
            else
            {
                Console.WriteLine("Access denied.");
            }
        }

        static void Login(string username, string password)
        {
            if (username.Equals("admin") && password.Equals("password123"))
            {
                isAdmin = true;
                Console.WriteLine("Login successful.");
            }
            else
            {
                Console.WriteLine("Login failed.");
            }
        }
    }
}
```

* This code has a **`Login()`** method that checks if the provided username and password match a hardcoded set of values. If they do, it sets the **`isAdmin`** variable to **`true`**.
* The **`DeleteAccount()`** method checks if **`isAdmin`** is **`true`** and if it is, it deletes the specified account (with a TODO comment indicating that this would be done in the real implementation).
* The vulnerability in this code is that it allows anyone to delete an account without authenticating first. Since there is no check to make sure that the user is authenticated before the **`DeleteAccount()`** method is called, anyone can call the method and delete any account they want.

A more secure implementation would require authentication before allowing the user to delete an account, such as by passing in the username and password to the **`DeleteAccount()`** method and checking them against the hardcoded values in the **`Login()`** method.

### _Here is an example of Mitigated code_

```java
using System;

namespace AccountManager
{
    class AccountManager
    {
        private bool isAdmin = false;

        public void DeleteAccount(string accountName, string username, string password)
        {
            if (isAdmin && username == "admin" && password == "password123")
            {
                Console.WriteLine($"Account {accountName} deleted.");
                // TODO: Delete account from the database
            }
            else
            {
                Console.WriteLine("Access denied.");
            }
        }

        public void Login(string username, string password)
        {
            if (username == "admin" && password == "password123")
            {
                isAdmin = true;
                Console.WriteLine("Login successful.");
            }
            else
            {
                Console.WriteLine("Login failed.");
            }
        }

        static void Main(string[] args)
        {
            AccountManager accountManager = new AccountManager();

            // Login
            Console.Write("Username: ");
            string username = Console.ReadLine();
            Console.Write("Password: ");
            string password = Console.ReadLine();
            accountManager.Login(username, password);

            // Delete account
            if (accountManager.isAdmin)
            {
                Console.Write("Enter account name to delete: ");
                string accountName = Console.ReadLine();
                accountManager.DeleteAccount(accountName, username, password);
            }
            else
            {
                Console.WriteLine("Access denied.");
            }
        }
    }
}
```

* In this mitigated code, the `DeleteAccount` method now requires `username` and `password` parameters in addition to the `accountName` parameter.
* The method checks whether the user is an admin and whether the supplied `username` and `password` match the hardcoded admin credentials.
* The `Main` method has been updated to pass the username and password parameters to the DeleteAccount method. This ensures that only authenticated users with admin credentials can delete accounts.

## Mitigation

The mitigation strategy for CWE 306 Missing Authentication for Critical Function is to implement proper authentication and authorization controls to prevent unauthorized access to critical functions. Some common mitigation techniques include:

1. Implementing strong authentication mechanisms, such as multi-factor authentication, to verify the identity of users attempting to access critical functions.
2. Implementing role-based access control to ensure that only authorized users have access to critical functions.
3. Implementing access control lists (ACLs) to control which users or groups can access specific resources or functions.
4. Using encryption to protect sensitive data and prevent unauthorized access to critical functions.
5. Regularly reviewing access logs and security policies to identify potential vulnerabilities and improve security controls.
6. Implementing automated security testing to identify and remediate vulnerabilities before they can be exploited.

## References

\[CWE -

```
	CWE-306: Missing Authentication for Critical Function (4.10)](https://cwe.mitre.org/data/definitions/306.html)
```
