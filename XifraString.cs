using System;
using System.Text;
using Gabriel.Cat.Extension;
//lo uso extendiendo string
namespace Gabriel.Cat.Seguretat
{
    public enum XifratText
    {
        TextDisimulat,TextDisimulatCaracters
    }
    public enum XifratPassword
    {
        MD5,Ninguno
    }
    public enum NivellXifrat
    {
        MoltBaix,
        Baix,
        Normal,
        Alt,
        MoltAlt
    }
    public static class XifraString
    {
        public static string Xifra(this string text, XifratText xifratText, NivellXifrat nivell, string password,XifratPassword xifratPassword)
        {
            switch (xifratPassword)
            {
                case XifratPassword.MD5: password = Serializar.GetBytes(password).Hash(); break;
            }
            return Xifra(text, xifratText, nivell, password);
        }

        public static string Xifra(this string text, XifratText xifrat, NivellXifrat nivell, string password)
        {
            string textXifrat = null;
            char[] caracteres;
            switch (xifrat)
            {
                case XifratText.TextDisimulat:
                    caracteres = new char[(90-64)*2];
                    for (int i = 0; i < caracteres.Length / 2; i++)
                        caracteres[i] = (char)(i + 65);
                    for (int i = caracteres.Length / 2; i < caracteres.Length; i++)
                        caracteres[i] = (char)(i - caracteres.Length / 2+ 97 );
                    textXifrat = ITextDisimulatXifra(text, nivell, password,caracteres); break;
                case XifratText.TextDisimulatCaracters:
                    caracteres = new char[255];
                    for (int i = 0; i < 255; i++)
                        caracteres[i] = (char)(i);  
                    textXifrat = ITextDisimulatXifra(text, nivell, password, caracteres); break;
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
        private static string ITextDisimulatXifra(string text, NivellXifrat nivell, string password,char[] caracteres)
        {
            //usa la password caracter a caracter para saber la posicion donde va el texto real...lo demas es pura basura
            StringBuilder textXifrat = new StringBuilder();

            if (text != "" && password != "")
            {
                text += caracteres[MiRandom.Next(caracteres.Length)];//lo pongo porque sino queda a la vista
                int posicionPassword = 0;
                for (int i = 0; i < text.Length; i++)
                {
                    for (int j = 0, finalBasura = ((int)password[posicionPassword]) % 71 * (int)nivell + 1; j < finalBasura; j++)//pongo los caracteres basura
                        textXifrat.Append(caracteres[MiRandom.Next(caracteres.Length)]);
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
            StringBuilder textDesxifrat = new StringBuilder();
            if (text != "" && password != "")
            {
                int posicionPassword = 0;
                int posicion = (((int)password[posicionPassword++]) % 71 * (int)nivell + 1);//me salto la basura
                while (posicion < text.Length)
                {
                    if (posicion < text.Length)
                        textDesxifrat.Append(text[posicion]);
                    posicion += (((int)password[posicionPassword]) % 71 * (int)nivell + 1) + 1;//me salto la basura
                    posicionPassword++;
                    if (posicionPassword == password.Length)
                        posicionPassword = 0;

                }
                textDesxifrat.Remove(textDesxifrat.Length - 1, 1);//quito el caracter centinela
            }
            else return text;
            return textDesxifrat.ToString();
        }
        #endregion
    }
}
