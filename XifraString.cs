using System;
using System.Text;
//lo uso extendiendo string
namespace Gabriel.Cat.Seguretat
{
    public enum XifratText
    {
        TextDisimulat
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

        public static string Xifra(this string text, XifratText xifrat, NivellXifrat nivell, string password)
        {
            string textXifrat = null;
            switch (xifrat)
            {
                case XifratText.TextDisimulat:textXifrat = ITextDisimulatXifra(text, nivell, password);break;
            }
            return textXifrat;
        }
        public static string Desxifra(this string text, XifratText xifrat, NivellXifrat nivell, string password)
        {
            string textXifrat = null;
            switch (xifrat)
            {
                case XifratText.TextDisimulat: textXifrat = ITextDisimulatDesxifra(text, nivell, password); break;
            }
            return textXifrat;
        }
        #region TextDisimulat
        private static string ITextDisimulatXifra(string text, NivellXifrat nivell, string password)
        {
            //usa la password caracter a caracter para saber la posicion donde va el texto real...lo demas es pura basura
            StringBuilder textXifrat = new StringBuilder();
            if (text != "" && password != "")
            {
                Random llavor = new Random();
                int posicionPassword = 0;
                for (int i = 0; i < text.Length; i++)
                {

                    for (int j = 0, finalBasura = (int)password[posicionPassword] * (int)nivell + 1; j < finalBasura; j++)//pongo los caracteres basura
                        textXifrat.Append((char)(llavor.Next(127) + 32));
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
                int posicion = 0;
                int posicionPassword = 0;
                //lo repito por el primer caso
                posicion += ((int)password[posicionPassword] * (int)nivell + 1);//me salto la basura
                posicionPassword++;
                if (posicionPassword == password.Length)
                    posicionPassword = 0;
                textDesxifrat.Append(text[posicion]);
                while (posicion < text.Length)
                {
                    posicion += ((int)password[posicionPassword] * (int)nivell + 1) + 1;//me salto la basura
                    posicionPassword++;
                    if (posicionPassword == password.Length)
                        posicionPassword = 0;
                    if (text.Length > posicion)
                        textDesxifrat.Append(text[posicion]);
                }
            }
            else return text;
            return textDesxifrat.ToString();
        }
        #endregion
    }
}
