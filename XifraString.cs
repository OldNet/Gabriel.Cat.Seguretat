using System;
using System.Text;
using Gabriel.Cat.Extension;
using System.Linq;
//lo uso extendiendo string
namespace Gabriel.Cat.Seguretat
{
    public enum XifratText
    {
        TextDisimulat,TextDisimulatCaracters
    }
    public enum XifratPassword
    {
        MD5,Cap
    }
    public enum NivellXifrat
    {
        MoltBaix,
        Baix,
        Normal,
        Alt,
        MoltAlt
    }
    /// <summary>
    /// Per escollir la clau
    /// </summary>
    public enum XifratMultiKey
    {
        Consecutiu,ConsecutiuIAlInreves,Clau
    }

    public static class XifraString
    {
        #region OneKey
        public static string Xifra(this string text, XifratText xifratText, NivellXifrat nivell, string password,XifratPassword xifratPassword)
        {
            return Xifra(text, xifratText, nivell, password,null);
        }
        private static string Xifra(this string text, XifratText xifratText, NivellXifrat nivell, string password, XifratPassword xifratPassword,object objAux)
        {
            switch (xifratPassword)
            {
                case XifratPassword.MD5: password = Serializar.GetBytes(password).Hash(); break;
            }
            return Xifra(text, xifratText, nivell, password,objAux);
        }
        public static string Xifra(this string text, XifratText xifrat, NivellXifrat nivell, string password)
        {
            return Xifra(text, xifrat, nivell, password, null);
        }
        private static string Xifra(this string text, XifratText xifrat, NivellXifrat nivell, string password,object objAux)
        {
            string textXifrat = null;
            char[] caracteres;
            switch (xifrat)
            {
                case XifratText.TextDisimulat:
                    caracteres = new char[(90 - 64) * 2];
                    for (int i = 0; i < caracteres.Length / 2; i++)
                        caracteres[i] = (char)(i + 65);
                    for (int i = caracteres.Length / 2; i < caracteres.Length; i++)
                        caracteres[i] = (char)(i - caracteres.Length / 2 + 97);
                    textXifrat = ITextDisimulatXifra(text, nivell, password, caracteres,objAux as char[]); break;
                case XifratText.TextDisimulatCaracters:
                    caracteres = new char[255];
                    for (int i = 0; i < 255; i++)
                        caracteres[i] = (char)(i);
                    textXifrat = ITextDisimulatXifra(text, nivell, password, caracteres, objAux as char[]); break;
            }
            return textXifrat;
        }
        public static string Desxifra(this string text, XifratText xifratText, NivellXifrat nivell, string password,XifratPassword xifratPassword)
        {
            switch (xifratPassword)
            {
                case XifratPassword.MD5: password = Serializar.GetBytes(password).Hash(); break;
            }
            return Desxifra(text, xifratText, nivell, password);
        }
        public static string Desxifra(this string text, XifratText xifrat, NivellXifrat nivell, string password)
        {
            string textXifrat = null;
            switch (xifrat)
            {
                case XifratText.TextDisimulat:
            	case XifratText.TextDisimulatCaracters:
            		textXifrat = ITextDisimulatDesxifra(text, nivell, password); break;
            }
            return textXifrat;
        }
        #region TextDisimulat
        private static string ITextDisimulatXifra(string text, NivellXifrat nivell, string password,char[] caracteresUsados,char[] caracteresNoUsados=null)//lo malo es que esos caracteres no usados como bulto hacen cantar a las que sin cifrar...
        {
            //usa la password caracter a caracter para saber la posicion donde va el texto real...lo demas es pura basura
            const int MOD = 71;
            StringBuilder textXifrat = new StringBuilder();
            int posicionPassword = 0;
            string aux="";
            if(caracteresNoUsados!=null)
            {
                for(int i=0;i<caracteresNoUsados.Length;i++)
                {
                    if (!aux.Contains(caracteresNoUsados[i]))
                        aux += caracteresNoUsados[i];
                }
                if (aux.Length < 255)
                {
                    while (aux.Contains(caracteresUsados[0]))
                        caracteresUsados[0] = (char)((1 + caracteresUsados[0]) % 255);
                    for (int i = 1; i < caracteresUsados.Length; i++)
                    {
                        if (aux.Contains(caracteresUsados[i]))
                            caracteresUsados[i] = caracteresUsados[i - 1];
                    }
                }
                else
                {
                    throw new ArgumentException("Se han excluido todos los caracteres posibles...");
                }
            }
            if (text != "" && password != "")
            {
                text += caracteresUsados[MiRandom.Next(caracteresUsados.Length)];//lo pongo porque sino queda a la vista
               
                for (int i = 0; i < text.Length; i++)
                {
                    for (int j = 0, finalBasura = ((int)password[posicionPassword]) % MOD * (int)nivell + 1; j < finalBasura; j++)//pongo los caracteres basura
                        textXifrat.Append(caracteresUsados[MiRandom.Next(caracteresUsados.Length)]);
                    textXifrat.Append(text[i]);//pongo el caracter a disimular
                    posicionPassword++;
                    if (posicionPassword == password.Length)
                        posicionPassword = 0;
                }
            }
            else return text;
            return textXifrat.ToString();
        }
        private static string ITextDisimulatDesxifra(string text, NivellXifrat nivell, string password)
        {
            //usa la password caracter a caracter para saber la posicion donde va el texto real...lo demas es pura basura
            const int MOD = 71;
            StringBuilder textDesxifrat = new StringBuilder();
            int posicionPassword = 0;
            
            if (text != "" && password != "")
            {
                
                int posicion = (((int)password[posicionPassword++]) % MOD * (int)nivell + 1);//me salto la basura
                while (posicion < text.Length)
                {
                    if (posicion < text.Length)
                        textDesxifrat.Append(text[posicion]);
                    posicion += (((int)password[posicionPassword]) % MOD * (int)nivell + 1) + 1;//me salto la basura
                    posicionPassword++;
                    if (posicionPassword == password.Length)
                        posicionPassword = 0;

                }
                if(textDesxifrat.Length>0)
                textDesxifrat.Remove(textDesxifrat.Length - 1, 1);//quito el caracter centinela
            }
            else return text;
            return textDesxifrat.ToString();
        }
        #endregion
        #endregion
        #region MultiKey
        #region Escollir clau per caracter
        public static string Xifra(this string textSenseXifrar, XifratText xifratText, XifratPassword xifratPassword, NivellXifrat nivell, string[] passwords, char caracterCanvi)
        {
            return Xifra(textSenseXifrar, new XifratText[] { xifratText }, new XifratPassword[] { xifratPassword },XifratMultiKey.Clau, nivell, passwords, caracterCanvi);
        }
        public static string Xifra(this string textSenseXifrar, XifratText[] xifratText, XifratPassword xifratPassword,XifratMultiKey escogerKey, NivellXifrat nivell, string[] passwords, char caracterCanvi)
        {
            return Xifra(textSenseXifrar, xifratText , new XifratPassword[] { xifratPassword },escogerKey, nivell, passwords, caracterCanvi);
        }
        public static string Xifra(this string textSenseXifrar, XifratText xifratText, XifratPassword[] xifratPassword, XifratMultiKey escogerKey, NivellXifrat nivell, string[] passwords, char caracterCanvi)
        {
            return Xifra(textSenseXifrar, new XifratText[] { xifratText }, xifratPassword,escogerKey , nivell, passwords, caracterCanvi);
        }
        public static string Xifra(this string textSenseXifrar,XifratText[] xifratText,XifratPassword[] xifratPassword, XifratMultiKey escogerKey, NivellXifrat nivell,string[] passwords,char caracterCanvi)
        {
            //el caracter no se puede usar en el textoSenseXifrar....lo paso a hexadecimal? y luego el caracter tiene que ser hexadecimal...
            if (xifratText == null || xifratText.Length == 0)
                throw new ArgumentException("es necessita un metode per xifrar");
            if (passwords == null || passwords.Length == 0 || String.IsNullOrEmpty(passwords[0]))
                throw new ArgumentException("Se necesita al menos una contraseña para cifrar");
            if (xifratPassword == null || xifratPassword.Length == 0)
                xifratPassword = new XifratPassword[] { XifratPassword.Cap };

            text txtXifrat = "";
            //xifro despres de trobarme el caracter canvio de clau aixi quan desxifro em trobare el caracter i sabre que tinc que canviar de clau.
            text subString = "";//fins trobar el caracter creo el text
            int numCanvis = 0;
            char[] caracterArray = new char[] { caracterCanvi };
            for (int i=0;i<textSenseXifrar.Length;i++)
            {
                
                if (textSenseXifrar[i]==caracterCanvi)
                {
                    //usar el orden para saber que posicion usar...
                    txtXifrat += subString.ToString().Xifra(xifratText[numCanvis % xifratText.Length], nivell, passwords[numCanvis % passwords.Length], xifratPassword[numCanvis % xifratPassword.Length], caracterArray) + caracterCanvi;
                    subString = "";
                    numCanvis++;
                }else
                { subString += textSenseXifrar[i]; }

            }
            if(subString!="") //usar el orden para saber que posicion usar...
                txtXifrat += subString.ToString().Xifra(xifratText[numCanvis % xifratText.Length], nivell, passwords[numCanvis % passwords.Length], xifratPassword[numCanvis % xifratPassword.Length], caracterArray);
            return txtXifrat;

        }

        //desxifro
        public static string Desxifra(this string textXifrat, XifratText xifratText, XifratPassword xifratPassword, XifratMultiKey escogerKey, NivellXifrat nivell, string[] passwords, char caracterCanvi)
        {
            return Desxifra(textXifrat, new XifratText[] { xifratText }, new XifratPassword[] { xifratPassword }, escogerKey, nivell, passwords, caracterCanvi);
        }
        public static string Desxifra(this string textXifrat, XifratText[] xifratText, XifratPassword xifratPassword, XifratMultiKey escogerKey, NivellXifrat nivell, string[] passwords, char caracterCanvi)
        {
            return Desxifra(textXifrat, xifratText, new XifratPassword[] { xifratPassword }, escogerKey, nivell, passwords, caracterCanvi);
        }
        public static string Desxifra(this string textXifrat, XifratText xifratText, XifratPassword[] xifratPassword, XifratMultiKey escogerKey, NivellXifrat nivell, string[] passwords, char caracterCanvi)
        {
            return Desxifra(textXifrat, new XifratText[] { xifratText }, xifratPassword, escogerKey, nivell, passwords, caracterCanvi);
        }
        public static string Desxifra(this string textXifrat, XifratText[] xifratText, XifratPassword[] xifratPassword, XifratMultiKey escogerKey, NivellXifrat nivell, string[] passwords, char caracterCanvi)
        {
            //poner lo del orden escogerKey,
            if (xifratText == null || xifratText.Length == 0)
                throw new ArgumentException("es necessita un metode per xifrar");
            if (passwords == null || passwords.Length == 0 || String.IsNullOrEmpty(passwords[0]))
                throw new ArgumentException("Se necesita al menos una contraseña para cifrar");
            if (xifratPassword == null || xifratPassword.Length == 0)
                xifratPassword = new XifratPassword[] { XifratPassword.Cap };

            text txtDesxifrat = "";
            //xifro despres de trobarme el caracter canvio de clau aixi quan desxifro em trobare el caracter i sabre que tinc que canviar de clau.
            text subString = "";//fins trobar el caracter creo el text
            int numCanvis = 0;
            for (int i = 0; i < textXifrat.Length; i++)
            {

                if (textXifrat[i] == caracterCanvi)
                {

                    txtDesxifrat += subString.ToString().Desxifra(xifratText[numCanvis % xifratText.Length], nivell, passwords[numCanvis % passwords.Length], xifratPassword[numCanvis % xifratPassword.Length])+caracterCanvi;
                    subString = "";
                    numCanvis++;
                }
                else
                { subString += textXifrat[i]; }

            }
            if (subString != "")
                txtDesxifrat += subString.ToString().Desxifra(xifratText[numCanvis % xifratText.Length], nivell, passwords[numCanvis % passwords.Length], xifratPassword[numCanvis % xifratPassword.Length]);
            return txtDesxifrat;

        }
        #endregion
        #endregion
    }
}
