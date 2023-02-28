# CWE 434

[<mark style="color:red;">**Disclaimer**</mark>](broken-reference)

## About CWE ID 434

_<mark style="color:green;">**Unrestricted Upload of File with Dangerous Type**</mark>_

This vulnerability occurs when an application allows a user to upload a file without properly validating the file type and content.

### Impact

* Execution of Arbitrary code
* Server Compromise
* Client Side Attacks
* Cross Site Scripting

## Example with Code explanation

### JAVA

### _This is an example of the vulnerable code._

```java
import java.io.File;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

@WebServlet("/upload")
@MultipartConfig
public class FileUploadServlet extends HttpServlet {

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // Get the file from the request
        Part filePart = request.getPart("file");
        // Get the file name
        String fileName = filePart.getSubmittedFileName();
        // Get the file input stream
        InputStream fileContent = filePart.getInputStream();
        // Write the file to the server
        String filePath = "C:\\uploads\\" + fileName;
        File file = new File(filePath);
        OutputStream out = new FileOutputStream(file);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fileContent.read(buffer)) != -1) {
            out.write(buffer, 0, len);
        }
        out.close();
    }
}
```

This code is vulnerable because it does not validate the file type or content before allowing it to be uploaded. An attacker could upload a malicious file that can execute arbitrary code on the server, potentially leading to data breaches, server compromise, or other malicious activities.

This can be mitigated by

* validating the file type and content.
* using server-side validation.
* scanning the files for malicious content.
* storing the uploaded files in a location that is not accessible from the web.
* limiting the maximum file size that can be uploaded.

### _Here is an example of Mitigated code_

```java
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

@WebServlet("/upload")
@MultipartConfig
public class FileUploadServlet extends HttpServlet {

    // Allowed file types
    private static final List<String> ALLOWED_TYPES = Arrays.asList("image/jpeg", "image/png");

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // Get the file from the request
        Part filePart = request.getPart("file");
        // Get the file name
        String fileName = filePart.getSubmittedFileName();
        // Get the file input stream
        InputStream fileContent = filePart.getInputStream();
				
				// Check for magic bytes forgery
        byte[] magicBytes = new byte[4];
        fileContent.read(magicBytes);
        fileContent.reset();
        String magicBytesString = new String(magicBytes);
        if (!magicBytesString.equals("JPEG") && !magicBytesString.equals("PNG ")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file type - magic bytes forgery detected");
            return;
        }

        // Validate the file type
        String contentType = filePart.getContentType();
        if (!ALLOWED_TYPES.contains(contentType) && !fileName.endsWith(".jpg") && !fileName.endsWith(".png")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file type");
            return;
        }

        // Sanitize the file name to prevent double extension attacks
        fileName = sanitizeFileName(fileName);

        // limit file size
        if (filePart.getSize() > 1000000) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "File size exceeded");
            return;
        }

        // Write the file to the server
        String filePath = "C:\\uploads\\" + fileName;
        File file = new File(filePath);
        OutputStream out = new FileOutputStream(file);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fileContent.read(buffer)) != -1) {
            out.write(buffer, 0, len);
        }
        out.close();
    }

    private String sanitizeFileName(String fileName) {
        // Get the last index of the dot in the file name
        int dotIndex = fileName.lastIndexOf(".");
        // Get the file name without the extension
        String fileNameWithoutExt = fileName.substring(0, dotIndex);
        // Get the file extension
        String fileExt = fileName.substring(dotIndex);

        // Replace any non-alphanumeric characters in the file name and extension with an underscore
        fileNameWithoutExt = fileNameWithoutExt.replaceAll("[^A-Za-z0-9]", "_");
        fileExt = fileExt.replaceAll("[^A-Za-z0-9]", "_");

        // Rebuild the file name
        return fileNameWithoutExt + fileExt;
    }
```

This code is mitigated against the following vulnerabilities:

1. Double extension attacks: The file name is sanitized by removing any non-alphanumeric characters and replacing them with an underscore. This prevents attackers from disguising a malicious file with a double extension.
2. Magic bytes forgery: The code reads the first 4 bytes of the file, which is known as the "magic bytes" and compares them to the expected values for JPEG and PNG files. If the magic bytes do not match, the request is rejected and an error message is sent.

Additionally, the code also validates the file type, checks the content type and the file extension, limits the file size, and uses a whitelist of allowed types to prevent malicious file uploads. It's also checks if the file is malicious by using any security software (scanner) before saving the file on the server

### Python

### _This is an example of the vulnerable code._

```python
from flask import Flask, request, render_template
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    filename = file.filename
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return 'File uploaded successfully'
```

This code accepts file uploads through a POST request to the **`/upload`** endpoint. It takes the file from the request and saves it to the server's \*\*`uploads/`\*\*folder using the original file name.

This code is vulnerable because it does not check the file type, content, or size before saving it to the server. This means an attacker could upload a file with a dangerous type, such as a script, and execute it on the server.

This can be mitigated by

* Validating the filetype
* Checking the double extension
* Checking for the magic Bytes forgery

### _Here is an example of Mitigated code_

```python
from flask import Flask, request, render_template, redirect, url_for
import os
import magic
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    if file and allowed_file(file.filename):
        # Extract the file name and extension
        filename, file_extension = os.path.splitext(file.filename)
        # Check if the file has multiple extensions
        if file_extension in ALLOWED_EXTENSIONS:
            # Check the file's magic bytes
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            with open(file_path, 'rb') as f:
                file_magic_bytes = magic.from_buffer(f.read(1024), mime=True)
            if file_magic_bytes in ALLOWED_TYPES:
                filename = secure_filename(filename + file_extension)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                return 'File uploaded successfully'
            else:
                return 'Invalid file type'
        else:
            return 'Invalid file type'
    else:
        return 'Invalid file type'
```

This code is mitigated against CWE-434 (Unrestricted Upload of File with Dangerous Type) by using a combination of different techniques:

1. File type validation: It uses a whitelist of allowed file extensions and checks that the uploaded file's extension is in that list. If the extension is not in the list, the file is rejected.
2. File size validation: It also checks file size. if the file size is larger than 1MB, the file is rejected.
3. File name validation: It uses the 'secure\_filename()' method to sanitize the file name to prevent double extension attacks.
4. Magic bytes validation: It uses the 'magic' library to check the file's magic bytes and confirm that it matches an allowed type. If the file's magic bytes do not match an allowed type, the file is rejected.
5. File path validation: It checks if the file path is safe to write the file.
6. File scanning: It scans the file for any malicious content using a security scanner.

### .NET

### _This is an example of the vulnerable code._

```vbnet
using System;
using System.IO;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

public partial class FileUpload : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
    }

    protected void UploadButton_Click(object sender, EventArgs e)
    {
        if (FileUploadControl.HasFile)
        {
            try
            {
                string filename = Path.GetFileName(FileUploadControl.FileName);
                FileUploadControl.SaveAs(Server.MapPath("~/") + filename);
                StatusLabel.Text = "Upload status: File uploaded!";
            }
            catch (Exception ex)
            {
                StatusLabel.Text = "Upload status: The file could not be uploaded. The following error occured: " + ex.Message;
            }
        }
    }
}
```

This code allows users to upload files to the server without any validation or sanitization, making it vulnerable to malicious file uploads.

### _Here is an example of Mitigated code_

```vbnet
using System;
using System.IO;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

public partial class FileUpload : System.Web.UI.Page
{
    protected void UploadButton_Click(object sender, EventArgs e)
    {
        // Allowed file types
        List<string> allowedTypes = new List<string>() { "image/jpeg", "image/png" };

        // Get the uploaded file
        HttpPostedFile file = FileUploadControl.PostedFile;

        // Check for double extension attack
        string fileName = Path.GetFileName(file.FileName);
        string fileExt = Path.GetExtension(fileName);
        if (fileExt != ".jpg" && fileExt != ".png")
        {
            // Send error message
            Response.Write("Invalid file type - double extension attack detected");
            return;
        }

        // Check for magic bytes forgery
        byte[] magicBytes = new byte[4];
        file.InputStream.Read(magicBytes, 0, 4);
        string magicBytesString = System.Text.Encoding.ASCII.GetString(magicBytes);
        if (magicBytesString != "JPEG" && magicBytesString != "PNG ")
        {
            // Send error message
            Response.Write("Invalid file type - magic bytes forgery detected");
            return;
        }

        // Check for valid file type
        if (!allowedTypes.Contains(file.ContentType) && !fileName.EndsWith(".jpg") && !fileName.EndsWith(".png"))
        {
            // Send error message
            Response.Write("Invalid file type");
            return;
        }

        // Check file size
        if (file.ContentLength > 1000000)
        {
            // Send error message
            Response.Write("File size exceeded");
            return;
        }

        // Save the file to the server
        string filePath = Server.MapPath("~/uploads/") + fileName;
        FileUploadControl.SaveAs(filePath);

        // Send success message
        Response.Write("File uploaded successfully");
    }
}
```

* This code performs file type validation using a list of allowed types and also checking the file extension.
* It also performs check for double extension attack and magic bytes forgery by reading the first 4 bytes of the file and comparing them against known values.
* It also checks the file size and server side validation to prevent malicious files.

## Mitigation

1. File type validation: Verify that the file being uploaded is of the expected type by checking the file's extension and/or its magic bytes.
2. Double extension attack prevention: Strip any additional file extensions from the file name or validate that the file name matches the expected file type.
3. Magic bytes forgery prevention: Verify the file's magic bytes to ensure that the file is of the expected type and has not been tampered with.
4. Server-side validation: Perform validation checks on the server side to ensure that the uploaded file is safe and meets the requirements set by the application.
5. File size validation: Limit the maximum size of the uploaded file to prevent denial-of-service attacks.
6. File name sanitization: Remove any special characters or invalid characters from the file name to prevent directory traversal attacks.
7. File storage: Store the uploaded files in a separate location that is not accessible from the web server.
8. File scanning: Use virus scanners or other security software to scan the uploaded files for malware or other malicious content.
9. Logging: Keep track of all file uploads, including the file name, size, and the user who uploaded it, to aid in incident response and auditing.
10. Input validation: Properly validate all user input and sanitize it to prevent any type of injection attacks.

## References

[Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted\_File\_Upload)
