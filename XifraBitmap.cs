using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using Gabriel.Cat;
namespace Gabriel.Cat.Seguretat
{
    public enum XifratImg
    {
        Normal
    }
  public static  class XifraBitmap
    {
        public static Bitmap Xifra(this Bitmap img, XifratImg xifrat, NivellXifrat nivell, string text)
        {
            return img.Xifra(xifrat, nivell, Serializar.GetBytes(text));
        }
        public static Bitmap Xifra(this Bitmap img, XifratImg xifrat, NivellXifrat nivell, byte[] dades)
        {
            Bitmap imgXifrada = img.Clone() as Bitmap;
            switch (xifrat)
            {
                //le pongo el texto
                case XifratImg.Normal:INormalXifrat(img,nivell, dades);break;
            }
            return imgXifrada;
        }

        public static byte[] Desxifra(this Bitmap img, XifratImg xifrat, NivellXifrat nivell)
        {
            byte[] dades=new byte[0];
            switch (xifrat)
            {
                //le quito el texto
                case XifratImg.Normal:dades = INormalDesXifrat(img,nivell);break;
            }
            return dades;
        }

        private static void INormalXifrat(Bitmap img, NivellXifrat nivell, byte[] dades)
        {
            //pone los bytes en la imagen
            byte[] imgBytes = img.GetBytes();
            //pongo los datos
            img.SetBytes(imgBytes);
        }
        private static byte[] INormalDesXifrat(Bitmap img, NivellXifrat nivell)
        {
            Llista<byte> dadesTrobades = new Llista<byte>();
            byte[] imgBytes = img.GetBytes();
            //trec les dades

            return dadesTrobades.ToTaula();
        }

    }
}
