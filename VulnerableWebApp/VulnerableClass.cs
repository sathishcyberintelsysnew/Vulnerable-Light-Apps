using System.Data;
using System.Security.Claims;
using System.Text;
using System.Xml;
using Microsoft.AspNetCore.DataProtection;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System;
using System.Threading;
using Microsoft.AspNetCore.DataProtection.KeyManagement;

namespace VulnerableWebApplication
{
    public class VulnerableClass
    {
        const string chars = "ABCDEFGHIFKLMNOPQRSTUVWXYZ";
        private static string secret { get; } = new string(Enumerable.Repeat(chars, 20).Select(s => s[new Random().Next(s.Length)]).ToArray());

        public static object VulnerableDeserialize(string json)
        {
            string f = "ReadOnly.txt";
            json = Misc.ScriptKiddiesFilter(json);

            if (!File.Exists(f))
            {
                File.WriteAllText(f, new Guid().ToString());
            }
            File.SetAttributes(f, FileAttributes.ReadOnly);

            JsonConvert.DeserializeObject<object>(json, new JsonSerializerSettings() { TypeNameHandling = TypeNameHandling.All });

            return "{\""+f+"\":\""+File.GetAttributes(f).ToString()+"\"}";
        }

        public static string VulnerableXmlParser(string xml)
        {

            xml = Misc.ScriptKiddiesFilter(xml);

            XmlReaderSettings settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.XmlResolver = new XmlUrlResolver();
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

        public static string VulnerableLogs(string str)
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

            return "{\"success\":true}";

        }

        public static string VulnerableQuery(string user, string passwd)
        {

            DataTable table = new DataTable();
            table.Columns.Add("user", typeof(string));
            table.Columns.Add("passwd", typeof(string));
            table.Rows.Add("root", "toor");
            table.Rows.Add("admin", "admin");
            table.Rows.Add("user", "");
            var DataSet = new DataSet();
            DataSet.Tables.Add(table);

            System.Diagnostics.Trace.WriteLine("login attempt for:\n" + user + "\n" + passwd + "\n");
            var result = DataSet.Tables[0].Select("user = '" + user + "' and passwd = '" + passwd + "'");

            return result.Length > 0 ? VulnerableGenerateToken(user) : "{\"success\":false}";

        }

        public static string VulnerableGenerateToken(string user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("id", user) }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static string VulnerableValidateToken(string token)
        {

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(secret);
            try
            {
                string header = token.Split(".")[0];
                try
                {
                    header = Encoding.UTF8.GetString(Convert.FromBase64String(header));
                }
                catch
                {
                    try
                    {
                        header = Encoding.UTF8.GetString(Convert.FromBase64String(header + "="));
                    }
                    catch
                    {
                        header = Encoding.UTF8.GetString(Convert.FromBase64String(header + "=="));
                    }
                }                
                if (!(header.Contains("none")))
                {
                    tokenHandler.ValidateToken(token, new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),
                        ValidateIssuer = false,
                        ValidateAudience = false,
                    }, out SecurityToken validatedToken);

                    var jwtToken = (JwtSecurityToken)validatedToken;
                    Console.WriteLine("Welcome {0}, your JWT token: {1} is valid!", jwtToken.Claims.First(x => x.Type == "id").Value, token);
                    return "{\"success\":true}";
                }
                else
                {
                    return "{\"success\":false}";

                }

            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.ToString());   
                return "{\"success\":true}";


            }

        }

        public static async Task<string> VulnerableWebRequest(string uri="https://localhost:3000/")
        {
            string rep = "{\"Result\":";

            if (uri.Contains("https://localhost"))
            {
                using HttpClient client = new();
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
                client.DefaultRequestHeaders.Add("User-Agent", "VulnerableApp");

                await exec(client, uri);

                
                static async Task exec(HttpClient client, string uri)
                {
                    var r = client.GetAsync(uri);
                    r.Result.EnsureSuccessStatusCode();
                    Console.WriteLine(await r.Result.Content.ReadAsStringAsync());

                }
            }
            return rep + "}";
        }


        public static string VulnerableObjectReference(int id, string token)
        {

            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(secret);
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                }, out SecurityToken validatedToken);
            }
            catch
            {
                return "{\"" + id + "\":\"Forbidden\"}";
            }



            DataTable table = new DataTable();
            table.Columns.Add("id", typeof(int));
            table.Columns.Add("adresse", typeof(string));
            table.Rows.Add(42, "3 rue Victor Hugo");
            table.Rows.Add(99, "4 place Napoléon");
            var DataSet = new DataSet();
            DataSet.Tables.Add(table);

            var result = from t in table.AsEnumerable() 
                                         where t.Field<int>("id").Equals(id) 
                                         select t.Field<string>("adresse") ;

            return "{\"" + id + "\":\"" + result.FirstOrDefault() + "\"}";

        }
    }
}
