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
        /// Construir o Objeto Recapctha.
        /// </summary>
        /// <param name="_key">Secret Key do Google Recaptcha, já tem um padrão.</param>
        public Recaptcha(string _key = null)
        {
            secret = _key ?? key;
        }

        /// <summary>
        /// Retornar o data-sitekey para imbutir no html.
        /// </summary>
        /// <param name="_siteKey">sitekey da Conta do Google que foi configurado!</param>
        /// <returns>sitekey da conta do Google</returns>
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
        /// Pega o IP do Usuário
        /// </summary>
        /// <returns>Retorna o IP do Usuário como String</returns>
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
        /// Verificar Resposta do Google, se foi validado ou não o Usuário.
        /// </summary>
        /// <param name="response">É o request form g-recaptcha-response</param>
        /// <returns>Um dicionário de dados contendo: \n
        /// ["success"] = true ou false \n
        /// ["error_codes"] = Empty ou código de erro.
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
    }


}
