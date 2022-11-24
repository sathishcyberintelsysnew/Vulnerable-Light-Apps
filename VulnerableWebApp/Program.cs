using VulnerableWebApplication;
using System.Web;



var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();


app.MapGet("/", () => "Welcome to VulnerableApp");

app.MapGet("/Log", async (string i) => await Task.FromResult(VulnerableClass.VulnerableLogs(HttpUtility.UrlDecode(i))));

app.MapGet("/Xml", async (string i) => await Task.FromResult(VulnerableClass.VulnerableXmlParser(HttpUtility.UrlDecode(i))));

app.MapGet("/Json", async (string i) => await Task.FromResult(VulnerableClass.VulnerableDeserialize(HttpUtility.UrlDecode(i))));

app.MapGet("/Auth", async (string u, string p) => await Task.FromResult(VulnerableClass.VulnerableQuery(HttpUtility.UrlDecode(u), HttpUtility.UrlDecode(p))));

app.MapGet("/Jwt", async (string i) => await Task.FromResult(VulnerableClass.VulnerableValidateToken(i)));

app.MapGet("/Req", async (string i) => await Task.FromResult(VulnerableClass.VulnerableWebRequest(i)));

app.Run("https://localhost:3000");

