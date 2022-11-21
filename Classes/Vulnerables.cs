using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Xml;
using System.Linq;
using System.Data;
using System.Security.Cryptography;

namespace Azerty_manager.Classes
{
    public class Vulnerables
    {

        public static object VulnerableDeserialize(string json)
        {
            return JsonConvert.DeserializeObject<object>(json, new JsonSerializerSettings()
            {
                TypeNameHandling = TypeNameHandling.All //unsafe
            });
        }

        public static string VulnerableXmlParser(string xml)
        {

            XmlReaderSettings settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Parse; //unsafe
            settings.XmlResolver = new XmlUrlResolver(); //unsafe
            settings.MaxCharactersFromEntities = 6000;

            using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(xml)))
            {
                XmlReader reader = XmlReader.Create(stream, settings);

                var xmlDocument = new XmlDocument();
                xmlDocument.XmlResolver = new XmlUrlResolver();
                xmlDocument.Load(reader);
                return xmlDocument.InnerText;
            }
        }

        public static void VulnerableLogs(string str)
        {
            string logFile = "Logs.html";
            string page = @"<!doctype html>
<html lang=""fr"">
<head>
<meta charset=""utf-8"">
<title> Titre de la page </title>
</head>
<body>
<h1>AzertyLogs<h1>
</body>
</html>";
            if (!File.Exists(logFile))
            {
                File.WriteAllText(logFile, page);
            }

            page = File.ReadAllText(logFile).Replace("</body>", "<p>" + str + "<p><br>" + Environment.NewLine + "</body>");
            Console.WriteLine(page);
            File.WriteAllText(logFile, page);

        }

        public static bool VulnerableQuery(string user, string passwd)
        {

            DataTable table = new DataTable();
            table.Columns.Add("user", typeof(string));
            table.Columns.Add("passwd", typeof(string));
            table.Rows.Add("root", "toor");
            table.Rows.Add("admin", "admin"); 
            table.Rows.Add("user", ""); 
            var DataSet = new DataSet();
            DataSet.Tables.Add(table);

            System.Diagnostics.Trace.WriteLine("login attempt for:\n" + user + "\n" + passwd + "\n" );
            var result = DataSet.Tables[0].Select("user = '" + user + "' and passwd = '" + passwd + "'");

            return result.Length > 0 ? true : false;   

        }

    }
}
