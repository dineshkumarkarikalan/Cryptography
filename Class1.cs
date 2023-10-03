using System;
using System.Text;
using Newtonsoft.Json;
public class Class1
{
	public Class1()
	{
	}
}
public class SMS
{
    public string from { get; set; }
    public string[] to { get; set; }
    public string body { get; set; }

    public SMS(string from, string[] to, string body)
    {
        this.from = from;
        this.to = to;
        this.body = body;
    }

    public async void sendSMS(SMS sms, string servicePlanId, string apiToken)
    {
        using (var client = new HttpClient())
        {
            client.DefaultRequestHeaders.Add("Authorization", "Bearer " + apiToken);
            string json = JsonConvert.SerializeObject(sms);
            var postData = new StringContent(json, Encoding.UTF8, "application/json");
            var request = await client.PostAsync("https://us.sms.api.sinch.com/xms/v1/" + servicePlanId + "/batches", postData);
            var response = await request.Content.ReadAsStringAsync();

            Console.WriteLine(response);
        }

    }

}
