using Azerty_manager.Classes;
using System;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.IO;
using System.Collections.ObjectModel;
using System.Threading;
using System.Text.RegularExpressions;


namespace azerty
{
    class Program
    {
        static void Main(string[] args)
        {
            string input = string.Empty;
            string f = "ReadOnly.txt";
            Int16 port = 443;
            string user = string.Empty;
            string passwd = string.Empty;


            while(!(Vulnerables.VulnerableQuery(user, passwd)))
            {
                Console.Write("user:");
                user = Console.ReadLine();
                Console.Write("password:");
                passwd = Console.ReadLine();
            }

            
            var certificate = new X509Certificate2("azerty-manager.pfx", "azertymanager");
            Console.WriteLine("Challanger starting on port: {0}", port);
            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();

            while (true)
            {
                try
                {
                    TcpClient client = listener.AcceptTcpClient();
                    NetworkStream stream = client.GetStream();
                    SslStream sslStream = new SslStream(stream, false);
                    sslStream.AuthenticateAsServer(certificate, false, System.Security.Authentication.SslProtocols.Tls12, false);

                    while (client.Connected)
                    {
                        string message = "message parsed";
                        rzo.sendMsg("Waiting for message", sslStream);
                        input = rzo.readMsg(sslStream, client);

                        Vulnerables.VulnerableLogs(input);

                        if (!File.Exists(f))
                        {
                            File.WriteAllText(f, new Guid().ToString());
                        }
                        File.SetAttributes(f, FileAttributes.ReadOnly);

                        try
                        {
                            Vulnerables.VulnerableDeserialize(input);
                            message = f + " is " + File.GetAttributes(f).ToString();

                            if (!((File.GetAttributes(f) & FileAttributes.ReadOnly) == FileAttributes.ReadOnly))
                            {
                                message = "Congrats ! deserialization flag is :" + File.ReadAllText("flag.txt");
                            }
                        }
                        catch(Exception ex)
                        {
                            Console.WriteLine(ex);
                        }


                        try
                        {
                            message = Vulnerables.VulnerableXmlParser(input);                           
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine(ex);
                        }

                        rzo.sendMsg(message, sslStream);

                    }
                }catch(Exception e)
                {
                    Console.WriteLine(e);
                }

            }


        }
    }
}