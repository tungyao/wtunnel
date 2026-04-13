// Auto-generated homepage HTML
#pragma once

#include <string>

namespace homepage {

const char* const HTML = "<!DOCTYPE html>\n"
"<html lang=\"en\">\n"
"<head>\n"
"    <meta charset=\"UTF-8\">\n"
"    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
"    <title>Welcome to CloudDocs</title>\n"
"    <style>\n"
"        * { margin: 0; padding: 0; box-sizing: border-box; }\n"
"        body {\n"
"            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;\n"
"            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\n"
"            min-height: 100vh;\n"
"            display: flex;\n"
"            align-items: center;\n"
"            justify-content: center;\n"
"        }\n"
"        .container {\n"
"            background: white;\n"
"            border-radius: 20px;\n"
"            padding: 60px;\n"
"            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);\n"
"            max-width: 600px;\n"
"            text-align: center;\n"
"        }\n"
"        h1 {\n"
"            color: #1a202c;\n"
"            font-size: 32px;\n"
"            margin-bottom: 16px;\n"
"        }\n"
"        p {\n"
"            color: #718096;\n"
"            line-height: 1.6;\n"
"        }\n"
"    </style>\n"
"</head>\n"
"<body>\n"
"    <div class=\"container\">\n"
"        <h1>Welcome to CloudDocs</h1>\n"
"        <p>Secure cloud storage for your team.</p>\n"
"    </div>\n"
"</body>\n"
"</html>\n";

inline std::string build_http_response() {
    std::string html = HTML;
    return "HTTP/1.1 200 OK\r\n"
           "Content-Type: text/html; charset=utf-8\r\n"
           "Connection: close\r\n"
           "Content-Length: " + std::to_string(html.size()) + "\r\n\r\n" + html;
}

}