using System;
using System.Collections.Generic;
using System.Web;
using System.Web.Helpers;
using System.Text;
using System.Net;

namespace Api.Google
{
    public class Recaptcha
    {
        private const string siteVerifyUrl = "https://www.google.com/recaptcha/api/siteverify?";
        private const string version = "C#_1.0";
        private static readonly string siteKey = "6Lf_EQYTAAAAADUMV4lX9SRGqyVKigbyNGnv3HR5";  //sitekey
        private const string key = "6Lf_EQYTAAAAAHAb42WgEBLFQevrBCNNSKmYTwTK"; //Secret Key
        private string secret { get; set; }

        /// <summary>
        /// Instantiates the object recaptcha.
        /// </summary>
        /// <param name="_key">Google Account Secret Key.</param>
        public Recaptcha(string _key = null)
        {
            secret = _key ?? key;
        }

        /// <summary>
        /// Return the data-sitekey for imbuing in html.
        /// </summary>
        /// <param name="_siteKey">Google Account SiteKey.</param>
        /// <returns>Google Account SiteKey as String.</returns>
        public static string dataSiteKey(string _siteKey = null)
        {
            return _siteKey ?? siteKey;
        }

        private string encodeQS(dynamic data)
        {
            return new StringBuilder()
                .AppendFormat("secret={0}&", HttpUtility.UrlEncode(secret))
                .AppendFormat("remoteip={0}&", HttpUtility.UrlEncode(data.remoteip))
                .AppendFormat("v={0}&", HttpUtility.UrlEncode(version))
                .AppendFormat("response={0}", HttpUtility.UrlEncode(data.response)).ToString();
        }

        private string submitHTTPGet(dynamic data)
        {
            return new WebClient().DownloadString(siteVerifyUrl + encodeQS(data));
        }

        /// <summary>
        /// Get the User IP
        /// </summary>
        /// <returns>Returns the User's IP as String</returns>
        private string getIp()
        {
            var Request = HttpContext.Current.Request;

            if (!string.IsNullOrEmpty(Request.ServerVariables["HTTP_X_FORWARDED_FOR"]))
            {
                return Request.ServerVariables["HTTP_X_FORWARDED_FOR"].Split(',')[0];
            }

            return Request.ServerVariables["REMOTE_ADDR"];
        }

        /// <summary>
        /// Verify Response of the Google.
        /// </summary>
        /// <param name="response">This is the request form g-recaptcha-response</param>
        /// <returns>A data dictionary containing:
        /// ["success"] = true or false 
        /// ["error_codes"] = Empty or error codes.
        /// </returns>
        public Dictionary<string, dynamic> verifyResponse(string response)
        {
            var answer = new Dictionary<string, dynamic>();

            if (string.IsNullOrEmpty(response))
            {
                answer.Add("success", false);
                answer.Add("error_codes", "missing-input");
                return answer;
            }

            dynamic sub = Json.Decode(submitHTTPGet(new { remoteip = getIp(), response = response }));

            if (sub["success"])
            {
                answer.Add("success", true);
            }
            else
            {
                answer.Add("success", false);
                answer.Add("error_codes", sub["error-codes"]);
            }

            return answer;
        }

        /// <summary>
        /// Verify Response of the Google.
        /// </summary>
        /// <param name="response">This is the request form g-recaptcha-response</param>
        /// <returns>True if the user is validated, otherwise False.</returns>
        public bool verifyResponse(string response)
        {
            return Json.Decode(submitHTTPGet(new { remoteip = getIp(), response = response }))["success"] ? true : false;
        }
    }


}
