﻿using System;
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
        Consecutiu,ConsecutiuIAlInreves
    }

    public static class XifraString
    {
        #region OneKey
        public static string Xifra(this string text, XifratText xifratText, NivellXifrat nivell, string password,XifratPassword xifratPassword)
        {
            if (String.IsNullOrEmpty(password))
                throw new ArgumentException("Es necesita una clau per dur a terme el xifrat");
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
//no se por que pero pierde los accentos...
            //usa la password caracter a caracter para saber la posicion donde va el texto real...lo demas es pura basura
            const int MOD = 71;
            const int MAXCHAR = 255;

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
        public static string Xifra(this string textSenseXifrar, string[] passwords, XifratText xifratText=XifratText.TextDisimulatCaracters, XifratPassword xifratPassword=XifratPassword.MD5, NivellXifrat nivell = NivellXifrat.MoltAlt, char caracterCanvi = '\n', XifratMultiKey escogerKey = XifratMultiKey.Consecutiu)
        {
            return Xifra(textSenseXifrar, new XifratText[] { xifratText }, new XifratPassword[] { xifratPassword }, passwords, nivell, caracterCanvi, escogerKey);
        }
        public static string Xifra(this string textSenseXifrar, XifratText[] xifratText, string[] passwords, XifratPassword xifratPassword=XifratPassword.MD5, NivellXifrat nivell = NivellXifrat.MoltAlt, char caracterCanvi = '\n', XifratMultiKey escogerKey = XifratMultiKey.Consecutiu)
        {
            return Xifra(textSenseXifrar, xifratText, new XifratPassword[] { xifratPassword }, passwords, nivell, caracterCanvi, escogerKey);
        }
        public static string Xifra(this string textSenseXifrar, string[] passwords, XifratPassword[] xifratPassword, XifratText xifratText=XifratText.TextDisimulatCaracters, NivellXifrat nivell = NivellXifrat.MoltAlt, char caracterCanvi = '\n', XifratMultiKey escogerKey = XifratMultiKey.Consecutiu)
        {
            return Xifra(textSenseXifrar, new XifratText[] { xifratText }, xifratPassword, passwords, nivell, caracterCanvi, escogerKey);
        }
        public static string Xifra(this string textSenseXifrar, XifratText[] xifratText, XifratPassword[] xifratPassword, string[] passwords, NivellXifrat nivell=NivellXifrat.MoltAlt, char caracterCanvi = '\n', XifratMultiKey escogerKey = XifratMultiKey.Consecutiu)
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
            for (int i=0;i<textSenseXifrar.Length;i++)
            {
                
                if (textSenseXifrar[i]==caracterCanvi)
                {
                    passwordActual = DamePasswordActual(escogerKey, numCanvis, passwords);
                    xifratTextActual = DameXifratTextActual(escogerKey, numCanvis, xifratText);
                    xifratPasswordActual = DameXifratPasswordActual(escogerKey, numCanvis, xifratPassword);
                    txtXifrat += subString.ToString().Xifra(xifratTextActual, nivell, passwordActual, xifratPasswordActual,caracterArray) + caracterCanvi;
                    subString = "";
                    numCanvis++;
                }else
                { subString += textSenseXifrar[i]; }

            }
            if (subString != "")
            {
                passwordActual = DamePasswordActual(escogerKey, numCanvis, passwords);
                xifratTextActual = DameXifratTextActual(escogerKey, numCanvis, xifratText);
                xifratPasswordActual = DameXifratPasswordActual(escogerKey, numCanvis, xifratPassword);
                txtXifrat += subString.ToString().Xifra(xifratTextActual, nivell, passwordActual, xifratPasswordActual, caracterArray);
            }
            return txtXifrat;

        }

        //desxifro
        public static string Desxifra(this string textXifrat, string[] passwords, XifratText xifratText=XifratText.TextDisimulatCaracters, XifratPassword xifratPassword=XifratPassword.MD5, XifratMultiKey escogerKey=XifratMultiKey.Consecutiu, NivellXifrat nivell=NivellXifrat.MoltAlt, char caracterCanvi='\n')

        {
            return Desxifra(textXifrat, new XifratText[] { xifratText }, new XifratPassword[] { xifratPassword }, passwords, escogerKey, nivell, caracterCanvi);
        }
        public static string Desxifra(this string textXifrat, XifratText[] xifratText, string[] passwords, XifratPassword xifratPassword=XifratPassword.MD5, XifratMultiKey escogerKey=XifratMultiKey.Consecutiu, NivellXifrat nivell= NivellXifrat.MoltAlt, char caracterCanvi='\n')
        {
            return Desxifra(textXifrat, xifratText, new XifratPassword[] { xifratPassword }, passwords, escogerKey, nivell, caracterCanvi);
        }
        public static string Desxifra(this string textXifrat, string[] passwords, XifratPassword[] xifratPassword, XifratText xifratText=XifratText.TextDisimulatCaracters, XifratMultiKey escogerKey=XifratMultiKey.Consecutiu, NivellXifrat nivell=NivellXifrat.MoltAlt, char caracterCanvi='\n')
        {
            return Desxifra(textXifrat, new XifratText[] { xifratText }, xifratPassword, passwords, escogerKey, nivell, caracterCanvi);
        }
        public static string Desxifra(this string textXifrat, XifratText[] xifratText, XifratPassword[] xifratPassword, string[] passwords, XifratMultiKey escogerKey = XifratMultiKey.Consecutiu, NivellXifrat nivell = NivellXifrat.MoltAlt, char caracterCanvi = '\n')
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
                    passwordActual = DamePasswordActual(escogerKey,numCanvis, passwords);
                    xifratTextActual = DameXifratTextActual(escogerKey, numCanvis, xifratText);
                    xifratPasswordActual = DameXifratPasswordActual(escogerKey, numCanvis, xifratPassword);
                    txtDesxifrat += subString.ToString().Desxifra(xifratTextActual, nivell, passwordActual,xifratPasswordActual)+caracterCanvi;
                    subString = "";
                    numCanvis++;
                }
                else
                { subString += textXifrat[i]; }

            }
            if (subString != "")
            {
                passwordActual = DamePasswordActual(escogerKey, numCanvis, passwords);
                xifratTextActual = DameXifratTextActual(escogerKey, numCanvis, xifratText);
                xifratPasswordActual = DameXifratPasswordActual(escogerKey, numCanvis, xifratPassword);
                txtDesxifrat += subString.ToString().Desxifra(xifratTextActual, nivell, passwordActual, xifratPasswordActual);
            }  return txtDesxifrat;

        }

        private static XifratPassword DameXifratPasswordActual(XifratMultiKey escogerKey, int contador, XifratPassword[] xifratPassword)
        {
            XifratPassword passwordActual = XifratPassword.Cap;
            int posicio;
            switch (escogerKey)
            {
                case XifratMultiKey.Consecutiu:
                    passwordActual = xifratPassword[contador % xifratPassword.Length]; break;
                case XifratMultiKey.ConsecutiuIAlInreves://repite el primero y el ultimo
                    posicio = contador / xifratPassword.Length;
                    if(posicio%2==0)
                    {
                        //si esta bajando
                        posicio = contador % xifratPassword.Length;
                    }
                    else
                    {
                        //esta subiendo
                        posicio = xifratPassword.Length-(contador % xifratPassword.Length)-1;
                    }
                    passwordActual = xifratPassword[posicio]; break;
            }
            return passwordActual;
        }

        private static XifratText DameXifratTextActual(XifratMultiKey escogerKey, int contador, XifratText[] xifratText)
        {
            XifratText passwordActual = XifratText.TextDisimulat;
            int posicio;
            switch (escogerKey)
            {
                case XifratMultiKey.Consecutiu:
                    passwordActual = xifratText[contador % xifratText.Length]; break;
                case XifratMultiKey.ConsecutiuIAlInreves://repite el primero y el ultimo
                    posicio = contador / xifratText.Length;
                    if (posicio % 2 == 0)
                    {
                        //si esta bajando
                        posicio = contador % xifratText.Length;
                    }
                    else
                    {
                        //esta subiendo
                        posicio = xifratText.Length - (contador % xifratText.Length) - 1;
                    }
                    passwordActual = xifratText[posicio]; break;
            }
            return passwordActual;
        }

        private static string DamePasswordActual(XifratMultiKey escogerKey, int contador, string[] passwords)
        {
            string passwordActual = null;
            int posicio;
            switch (escogerKey)
            {
                case XifratMultiKey.Consecutiu:
                    passwordActual = passwords[contador % passwords.Length]; break;
                case XifratMultiKey.ConsecutiuIAlInreves:
                    posicio = contador / passwords.Length;
                    if (posicio % 2 == 0)//repite el primero y el ultimo
                    {
                        //si esta bajando
                        posicio = contador % passwords.Length;
                    }
                    else
                    {
                        //esta subiendo
                        posicio = passwords.Length - (contador % passwords.Length) - 1;
                    }
                    passwordActual = passwords[posicio]; break;

            }
            return passwordActual;
        }
        #endregion
        #endregion
    }
}
