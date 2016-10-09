using Gabriel.Cat.Extension;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Gabriel.Cat.Seguretat
{
  public static  class XifraBytes
    {
        static readonly Encoding encoding= System.Text.ASCIIEncoding.UTF8;
        #region OneKey
        public static byte[] Encrypt(this byte[] bytes, XifratText xifratText, NivellXifrat nivell, string password, XifratPassword xifratPassword)
        {
            if (String.IsNullOrEmpty(password))
                throw new ArgumentException("Es necesita una clau per dur a terme el xifrat");
            return Encrypt(bytes, xifratText, nivell, password, xifratPassword, null);
        }
        internal static byte[] Encrypt(this byte[] bytes, XifratText xifratText, NivellXifrat nivell, string password, XifratPassword xifratPassword, params dynamic[] objs)
        {
            return encoding.GetBytes(encoding.GetString(bytes).Encrypt(xifratText, nivell, password, xifratPassword, objs));
        }
        public static byte[] Encrypt(this byte[] bytes, XifratText xifrat, NivellXifrat nivell, string password)
        {
            return Encrypt(bytes, xifrat, nivell, password, null);
        }
        internal static byte[] Encrypt(this byte[] bytes, XifratText xifrat, NivellXifrat nivell, string password, params dynamic[] objs)
        {
            return encoding.GetBytes(encoding.GetString(bytes).Encrypt(xifrat, nivell, password,objs));
        }
        public static byte[] Decrypt(this byte[] bytes, XifratText xifratText, NivellXifrat nivell, string password, XifratPassword xifratPassword)
        {
            return Decrypt(bytes, xifratText, nivell, password, xifratPassword, null);
        }
        private static byte[] Decrypt(this byte[] bytes, XifratText xifratText, NivellXifrat nivell, string password, XifratPassword xifratPassword, params dynamic[] objs)
        {
            return encoding.GetBytes(encoding.GetString(bytes).Decrypt(xifratText, nivell, password, xifratPassword, objs));
        }
        public static byte[] Decrypt(this byte[] bytes, XifratText xifrat, NivellXifrat nivell, string password)
        {
            return Decrypt(bytes, xifrat, nivell, password, null);
        }
        internal static byte[] Decrypt(this byte[] bytes, XifratText xifrat, NivellXifrat nivell, string password, params dynamic[] objs)
        {
            return encoding.GetBytes(encoding.GetString(bytes).Decrypt(xifrat, nivell, password,  objs));
        }

        #endregion
        #region MultiKey
        #region Escollir clau per caracter
   
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, XifratText xifratText = XifratText.TextDisimulatCaracters, XifratPassword xifratPassword = XifratPassword.MD5, NivellXifrat nivell = NivellXifrat.MoltAlt, Ordre escogerKey = Ordre.Consecutiu, char caracterCanvi = '\n')
        {
            return encoding.GetBytes(encoding.GetString(bytes).Encrypt(new XifratText[] { xifratText }, new XifratPassword[] { xifratPassword }, passwords, nivell, escogerKey, caracterCanvi));
        }
        public static byte[] Encrypt(this byte[] bytes, XifratText[] xifratText, string[] passwords, XifratPassword xifratPassword = XifratPassword.MD5, NivellXifrat nivell = NivellXifrat.MoltAlt, Ordre escogerKey = Ordre.Consecutiu, char caracterCanvi = '\n')
        {
            return encoding.GetBytes(encoding.GetString(bytes).Encrypt( xifratText, new XifratPassword[] { xifratPassword }, passwords, nivell, escogerKey, caracterCanvi));
        }
        public static byte[] Encrypt(this byte[] bytes, string[] passwords, XifratPassword[] xifratPassword, XifratText xifratText = XifratText.TextDisimulatCaracters, NivellXifrat nivell = NivellXifrat.MoltAlt, Ordre escogerKey = Ordre.Consecutiu, char caracterCanvi = '\n')
        {
            return encoding.GetBytes(encoding.GetString(bytes).Encrypt( new XifratText[] { xifratText }, xifratPassword, passwords, nivell, escogerKey, caracterCanvi));
        }
        public static byte[] Encrypt(this byte[] bytes, XifratText[] xifratText, XifratPassword[] xifratPassword, string[] passwords, NivellXifrat nivell = NivellXifrat.MoltAlt, Ordre escogerKey = Ordre.Consecutiu, char caracterCanvi = '\n')
        {
            return encoding.GetBytes(encoding.GetString(bytes).Encrypt(xifratText, xifratPassword, passwords, nivell, escogerKey, caracterCanvi));
        }
        //desxifro
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, XifratText xifratText = XifratText.TextDisimulatCaracters, XifratPassword xifratPassword = XifratPassword.MD5, NivellXifrat nivell = NivellXifrat.MoltAlt, Ordre escogerKey = Ordre.Consecutiu, char caracterCanvi = '\n')
        {
            return encoding.GetBytes(encoding.GetString(bytes).Decrypt( new XifratText[] { xifratText }, new XifratPassword[] { xifratPassword }, passwords, nivell, escogerKey, caracterCanvi));
        }
        public static byte[] Decrypt(this byte[] bytes, XifratText[] xifratText, string[] passwords, XifratPassword xifratPassword = XifratPassword.MD5, NivellXifrat nivell = NivellXifrat.MoltAlt, Ordre escogerKey = Ordre.Consecutiu, char caracterCanvi = '\n')
        {
            return encoding.GetBytes(encoding.GetString(bytes).Decrypt(xifratText, new XifratPassword[] { xifratPassword }, passwords, nivell, escogerKey, caracterCanvi));
        }
        public static byte[] Decrypt(this byte[] bytes, string[] passwords, XifratPassword[] xifratPassword, XifratText xifratText = XifratText.TextDisimulatCaracters, NivellXifrat nivell = NivellXifrat.MoltAlt, Ordre escogerKey = Ordre.Consecutiu, char caracterCanvi = '\n')
        {
            return encoding.GetBytes(encoding.GetString(bytes).Decrypt( new XifratText[] { xifratText }, xifratPassword, passwords, nivell, escogerKey, caracterCanvi));
        }
        public static byte[] Decrypt(this byte[] bytes, XifratText[] xifratText, XifratPassword[] xifratPassword, string[] passwords, NivellXifrat nivell = NivellXifrat.MoltAlt, Ordre escogerKey = Ordre.Consecutiu, char caracterCanvi = '\n')
        {
            return encoding.GetBytes(encoding.GetString(bytes).Decrypt( xifratText, xifratPassword, passwords, nivell, escogerKey, caracterCanvi));

        }

        #endregion
        #endregion
    }
}
