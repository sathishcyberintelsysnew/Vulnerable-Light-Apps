using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.IO;
using System.Collections.ObjectModel;
using System.Threading;

namespace Azerty_manager.Classes
{
    public class rzo
    {
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
    }
}

