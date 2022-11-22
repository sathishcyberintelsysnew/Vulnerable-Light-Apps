# Azerty-manager
 
## Vulnerable Console Apps for educational purposes

* CWE-89	Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
* CWE-119	Improper Restriction of Operations within the Bounds of a Memory Buffer
* CWE-502	Deserialization of Untrusted Data
* CWE-611	Improper Restriction of XML External Entity Reference
* CWE-79	Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
* CWE-326	Inadequate Encryption Strength
* CWE-287	Improper Authentication
* CWE-521	Weak Password Requirements
* CWE-532	Insertion of Sensitive Information into Log File
* CWE-798	Use of Hard-coded Credentials 
* CWE-1270  Generation of Incorrect Security Tokens
* CWE-284: Improper Access Control

## Create just one socket and stay focused on vulnerable code ;)

```c#

        public static string readMsg(SslStream sslStream, TcpClient client)
        {
            byte[] buffer = new byte[client.ReceiveBufferSize];
            int bytesRead = sslStream.Read(buffer, 0, client.ReceiveBufferSize);
            return Encoding.UTF8.GetString(buffer, 0, bytesRead);
        }
        public static void sendMsg(string message, SslStream sslStream)
        {
            sslStream.Write(Encoding.UTF8.GetBytes(message), 0, Encoding.UTF8.GetBytes(message).Length);
        }

        public static bool CertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        string message = string.Empty;
        TcpClient client = new TcpClient("127.0.0.1", 443);
        var stream = client.GetStream();
        SslStream sslStream = new SslStream(stream, false, new RemoteCertificateValidationCallback(CertificateValidationCallback));
        sslStream.AuthenticateAsClient("client", null, System.Security.Authentication.SslProtocols.Tls12, false);
        message += readMsg(sslStream, client) + Environment.NewLine;
        sendMsg("YOUR INPUT HERE", sslStream);
        message += readMsg(sslStream, client) + Environment.NewLine;

```