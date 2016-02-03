using System;
using System.Text;
using Gabriel.Cat.Extension;
using System.Linq;
//lo uso extendiendo string
namespace Gabriel.Cat.Seguretat
{
    public enum XifratText
    {
        TextDisimulat,
        TextDisimulatCaracters,
        Cesar
    }
    public enum XifratPassword
    {
        MD5,
        Cap
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


    public static class XifraString
    {
        delegate char MetodoCesar(char[] caracteresNoPermitidos,char caracterTexto);
        const int MAXCHAR = 255, MINCHAR = 0;



        #region OneKey
        public static string Xifra(this string text, XifratText xifratText, NivellXifrat nivell, string password, XifratPassword xifratPassword)
        {
            if (String.IsNullOrEmpty(password))
                throw new ArgumentException("Es necesita una clau per dur a terme el xifrat");
            return Xifra(text, xifratText, nivell, password, null);
        }
        private static string Xifra(this string text, XifratText xifratText, NivellXifrat nivell, string password, XifratPassword xifratPassword, object objAux)
        {
            switch (xifratPassword)
            {
                case XifratPassword.MD5:
                    password = Serializar.GetBytes(password).Hash();
                    break;
            }
            return Xifra(text, xifratText, nivell, password, objAux);
        }
        public static string Xifra(this string text, XifratText xifrat, NivellXifrat nivell, string password)
        {
            return Xifra(text, xifrat, nivell, password, null);
        }
        private static string Xifra(this string text, XifratText xifrat, NivellXifrat nivell, string password, params dynamic[] objs)
        {
            if (String.IsNullOrEmpty(password))
                throw new ArgumentException("Es necesita una clau per dur a terme el xifrat");
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
                    textXifrat = ITextDisimulatXifra(text, nivell, password, caracteres, objs[0]);
                    break;
                case XifratText.TextDisimulatCaracters:
                    caracteres = new char[255];
                    for (int i = 0; i < 255; i++)
                        caracteres[i] = (char)(i);
                    textXifrat = ITextDisimulatXifra(text, nivell, password, objs[0]);
                    break;
                case XifratText.Cesar:
                    if (objs != null)
                        textXifrat = CesarXifrar(text, password, nivell, objs[1], objs[0]);
                    else {
                        textXifrat = CesarXifrar(text, password, nivell);
                    }
                    break;
            }
            return textXifrat;
        }
        public static string Desxifra(this string text, XifratText xifratText, NivellXifrat nivell, string password, XifratPassword xifratPassword)
        {
            switch (xifratPassword)
            {
                case XifratPassword.MD5:
                    password = Serializar.GetBytes(password).Hash();
                    break;
            }
            return Desxifra(text, xifratText, nivell, password);
        }
        public static string Desxifra(this string text, XifratText xifrat, NivellXifrat nivell, string password)
        {
            return Desxifra(text, xifrat, nivell, password, null);
        }
        private static string Desxifra(this string text, XifratText xifrat, NivellXifrat nivell, string password, params dynamic[] objs)
        {
            string textoDescifrado = null;
            switch (xifrat)
            {
                case XifratText.TextDisimulat:
                case XifratText.TextDisimulatCaracters:
                    textoDescifrado = ITextDisimulatDesxifra(text, nivell, password);
                    break;
                case XifratText.Cesar:
                    if (objs != null)
                        textoDescifrado = CesarDesxifrar(text, password, nivell, objs[1], objs[0]);
                    else {
                        textoDescifrado = CesarDesxifrar(text, password, nivell);
                    }
                    break;
            }
            return textoDescifrado;
        }
        #region Cesar
        //en desarollo...no funciona con todos los caracteres ASCII
        private static string CesarXifrar(string texto, string password, NivellXifrat nivell, Ordre ordre = Ordre.Consecutiu, char[] caracteresNoPermitidos = null)
        {

            MetodoCesar metodoPonerCaracterValidoCifrar = (caracteresQueNoSePuedenUsar,caracterTexto) =>
            {
                while (caracteresQueNoSePuedenUsar.Contains(caracterTexto))
                {
                    if (caracterTexto == MAXCHAR)
                        caracterTexto = (char)MINCHAR;
                    else 
                        caracterTexto++;                   
                }
                return caracterTexto;
            };
            return Cesar(metodoPonerCaracterValidoCifrar, texto, password, nivell, ordre, caracteresNoPermitidos);
        }
        private static string CesarDesxifrar(string textXifrat, string password, NivellXifrat nivell, Ordre ordre = Ordre.Consecutiu, char[] caracteresNoPermitidos = null)
        {
            MetodoCesar metodoPonerCaracterValidoDescifrar = (caracteresQueNoSePuedenUsar,caracterTexto) =>
            {
                while (caracteresQueNoSePuedenUsar.Contains(caracterTexto))
                {
                    if (caracterTexto == MINCHAR)
                        caracterTexto = (char)MAXCHAR;
                    else
                        caracterTexto--;
                }
                return caracterTexto;
            };
            return Cesar(metodoPonerCaracterValidoDescifrar, textXifrat, password, nivell, ordre, caracteresNoPermitidos);
        }
        private static string Cesar(MetodoCesar metodo, string texto, string password, NivellXifrat nivell, Ordre ordre = Ordre.Consecutiu, char[] caracteresNoPermitidos = null)
        {

            char caracterTexto, caracterActualPassword;
            char[] caracteresPassword = password.ToCharArray();
            text textoCifrado = "";
            if (caracteresNoPermitidos == null)
                caracteresNoPermitidos = new char[0];
            else if (caracteresNoPermitidos.Length == MAXCHAR)
            {
                if (caracteresNoPermitidos.Distinct().ToArray().Length == MAXCHAR)
                    throw new ArgumentException("Se han descartado todos los caracteres validos...");
            }
            for (int i = 0; i < texto.Length; i++)
            {
                caracterActualPassword = caracteresPassword.DameElementoActual(ordre, i);
                caracterTexto = texto[i];
                caracterTexto = (char)((caracterActualPassword + caracterTexto) % MAXCHAR);
                textoCifrado += metodo(caracteresNoPermitidos, caracterTexto);
            }
            return textoCifrado;
        }
        #endregion
        #region TextDisimulat
        private static string ITextDisimulatXifra(string text, NivellXifrat nivell, string password, char[] caracteresUsados, char[] caracteresNoUsados = null)//lo malo es que esos caracteres no usados como bulto hacen cantar a las que sin cifrar...
        {
            //no se por que pero pierde los accentos...
            //usa la password caracter a caracter para saber la posicion donde va el texto real...lo demas es pura basura
            const int MOD = 71;
            const int MAXCHAR = 255;

            StringBuilder textXifrat = new StringBuilder();
            int posicionPassword = 0;
            string aux = "";

            if (caracteresNoUsados != null)
            {
                for (int i = 0; i < caracteresNoUsados.Length; i++)
                {
                    if (!aux.Contains(caracteresNoUsados[i]))
                        aux += caracteresNoUsados[i];
                }
                if (aux.Length < MAXCHAR)
                {
                    while (aux.Contains(caracteresUsados[0]))
                        caracteresUsados[0] = (char)((1 + caracteresUsados[0]) % MAXCHAR);
                    for (int i = 1; i < caracteresUsados.Length; i++)
                    {
                        if (aux.Contains(caracteresUsados[i]))
                            caracteresUsados[i] = caracteresUsados[i - 1];
                    }
                }
                else {
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
            else
                return text;
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
                if (textDesxifrat.Length > 0)
                    textDesxifrat.Remove(textDesxifrat.Length - 1, 1);//quito el caracter centinela
            }
            else
                return text;
            return textDesxifrat.ToString();
        }
        #endregion
        #endregion
        #region MultiKey
        #region Escollir clau per caracter
        public static string Xifra(this string textSenseXifrar, string[] passwords, XifratText xifratText = XifratText.TextDisimulatCaracters, XifratPassword xifratPassword = XifratPassword.MD5, NivellXifrat nivell = NivellXifrat.MoltAlt, char caracterCanvi = '\n', Ordre escogerKey = Ordre.Consecutiu)
        {
            return Xifra(textSenseXifrar, new XifratText[] { xifratText }, new XifratPassword[] { xifratPassword }, passwords, nivell, caracterCanvi, escogerKey);
        }
        public static string Xifra(this string textSenseXifrar, XifratText[] xifratText, string[] passwords, XifratPassword xifratPassword = XifratPassword.MD5, NivellXifrat nivell = NivellXifrat.MoltAlt, char caracterCanvi = '\n', Ordre escogerKey = Ordre.Consecutiu)
        {
            return Xifra(textSenseXifrar, xifratText, new XifratPassword[] { xifratPassword }, passwords, nivell, caracterCanvi, escogerKey);
        }
        public static string Xifra(this string textSenseXifrar, string[] passwords, XifratPassword[] xifratPassword, XifratText xifratText = XifratText.TextDisimulatCaracters, NivellXifrat nivell = NivellXifrat.MoltAlt, char caracterCanvi = '\n', Ordre escogerKey = Ordre.Consecutiu)
        {
            return Xifra(textSenseXifrar, new XifratText[] { xifratText }, xifratPassword, passwords, nivell, caracterCanvi, escogerKey);
        }
        public static string Xifra(this string textSenseXifrar, XifratText[] xifratText, XifratPassword[] xifratPassword, string[] passwords, NivellXifrat nivell = NivellXifrat.MoltAlt, char caracterCanvi = '\n', Ordre escogerKey = Ordre.Consecutiu)
        {

            if (xifratText == null || xifratText.Length == 0)
                throw new ArgumentException("es necessita un metode per xifrar");
            if (passwords == null || passwords.Length == 0 || String.IsNullOrEmpty(passwords[0]))
                throw new ArgumentException("Se necesita al menos una contraseña para cifrar");
            if (xifratPassword == null || xifratPassword.Length == 0)
                xifratPassword = new XifratPassword[] { XifratPassword.Cap };

            text txtXifrat = "";
            //xifro avans de trobarme el caracter despres poso el caracter tal qual i canvio de clau aixi quan desxifro em trobare el caracter i sabre que tinc que canviar de clau.
            text subString = "";//fins trobar el caracter creo el text
            int numCanvis = 0;
            string passwordActual;
            XifratText xifratTextActual;
            XifratPassword xifratPasswordActual;
            char[] caracterArray = new char[] { caracterCanvi };
            for (int i = 0; i < textSenseXifrar.Length; i++)
            {

                if (textSenseXifrar[i] == caracterCanvi)
                {
                    passwordActual = passwords.DameElementoActual(escogerKey, numCanvis);
                    xifratTextActual = xifratText.DameElementoActual(escogerKey, numCanvis);
                    xifratPasswordActual = xifratPassword.DameElementoActual(escogerKey, numCanvis);
                    txtXifrat += subString.ToString().Xifra(xifratTextActual, nivell, passwordActual, xifratPasswordActual, caracterArray, escogerKey) + caracterCanvi;
                    subString = "";
                    numCanvis++;
                }
                else {
                    subString += textSenseXifrar[i];
                }

            }
            if (subString != "")
            {
                passwordActual = passwords.DameElementoActual(escogerKey, numCanvis);
                xifratTextActual = xifratText.DameElementoActual(escogerKey, numCanvis);
                xifratPasswordActual = xifratPassword.DameElementoActual(escogerKey, numCanvis);
                txtXifrat += subString.ToString().Xifra(xifratTextActual, nivell, passwordActual, xifratPasswordActual, caracterArray, escogerKey);
            }
            return txtXifrat;

        }

        //desxifro
        public static string Desxifra(this string textXifrat, string[] passwords, XifratText xifratText = XifratText.TextDisimulatCaracters, XifratPassword xifratPassword = XifratPassword.MD5, Ordre escogerKey = Ordre.Consecutiu, NivellXifrat nivell = NivellXifrat.MoltAlt, char caracterCanvi = '\n')
        {
            return Desxifra(textXifrat, new XifratText[] { xifratText }, new XifratPassword[] { xifratPassword }, passwords, escogerKey, nivell, caracterCanvi);
        }
        public static string Desxifra(this string textXifrat, XifratText[] xifratText, string[] passwords, XifratPassword xifratPassword = XifratPassword.MD5, Ordre escogerKey = Ordre.Consecutiu, NivellXifrat nivell = NivellXifrat.MoltAlt, char caracterCanvi = '\n')
        {
            return Desxifra(textXifrat, xifratText, new XifratPassword[] { xifratPassword }, passwords, escogerKey, nivell, caracterCanvi);
        }
        public static string Desxifra(this string textXifrat, string[] passwords, XifratPassword[] xifratPassword, XifratText xifratText = XifratText.TextDisimulatCaracters, Ordre escogerKey = Ordre.Consecutiu, NivellXifrat nivell = NivellXifrat.MoltAlt, char caracterCanvi = '\n')
        {
            return Desxifra(textXifrat, new XifratText[] { xifratText }, xifratPassword, passwords, escogerKey, nivell, caracterCanvi);
        }
        public static string Desxifra(this string textXifrat, XifratText[] xifratText, XifratPassword[] xifratPassword, string[] passwords, Ordre escogerKey = Ordre.Consecutiu, NivellXifrat nivell = NivellXifrat.MoltAlt, char caracterCanvi = '\n')
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
            string passwordActual;
            XifratText xifratTextActual;
            XifratPassword xifratPasswordActual;
            int numCanvis = 0;
            for (int i = 0; i < textXifrat.Length; i++)
            {

                if (textXifrat[i] == caracterCanvi)
                {
                    passwordActual = passwords.DameElementoActual(escogerKey, numCanvis);
                    xifratTextActual = xifratText.DameElementoActual(escogerKey, numCanvis);
                    xifratPasswordActual = xifratPassword.DameElementoActual(escogerKey, numCanvis);
                    txtDesxifrat += subString.ToString().Desxifra(xifratTextActual, nivell, passwordActual, xifratPasswordActual, escogerKey) + caracterCanvi;
                    subString = "";
                    numCanvis++;
                }
                else {
                    subString += textXifrat[i];
                }

            }
            if (subString != "")
            {
                passwordActual = passwords.DameElementoActual(escogerKey, numCanvis);
                xifratTextActual = xifratText.DameElementoActual(escogerKey, numCanvis);
                xifratPasswordActual = xifratPassword.DameElementoActual(escogerKey, numCanvis);
                txtDesxifrat += subString.ToString().Desxifra(xifratTextActual, nivell, passwordActual, xifratPasswordActual, escogerKey);
            }
            return txtDesxifrat;

        }

        #endregion
        #endregion
    }
}
