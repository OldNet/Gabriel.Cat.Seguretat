using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using Gabriel.Cat;
using System.Collections;

namespace Gabriel.Cat.Seguretat
{
    public enum XifratImg
    {
        Normal
    }
    public static class XifraBitmap
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
                //le pongo los datos
                case XifratImg.Normal: INormalXifrat(imgXifrada, nivell, dades); break;
            }
            return imgXifrada;
        }

        public static byte[] Desxifra(this Bitmap img, XifratImg xifrat, NivellXifrat nivell)
        {
            byte[] dades = new byte[0];
            switch (xifrat)
            {
                //le quito los datos
                case XifratImg.Normal: dades = INormalDesXifrat(img, nivell); break;
            }
            return dades;
        }
        public static long MaxBytesXifrat(this Bitmap bmp,NivellXifrat nivell)
        {
            return bmp.GetBytes().LongLength / (8 * ((int)nivell + 1));
        }

        private static void INormalXifrat(Bitmap img, NivellXifrat nivell, byte[] dades)
        {
            //pone los bytes en la imagen

            byte[] bytesImg = img.GetBytes();
            bool[] imgBits = bytesImg.ToBits();
            const int BITSBYTE = 8;
            byte[] longitud = Serializar.GetBytes(dades.LongLength * BITSBYTE);
            bool[] bitsLong = longitud.ToBits();
            bool[] bitsAPoner = bitsLong.AfegirValors(dades.ToBits()).ToArray();
            if (imgBits.LongLength < bitsAPoner.LongLength * ((int)nivell + 1))
                throw new Exception("La imatge no pot contenir les dades amb el nivell de seguretat posat!");

            for (int j = 0, i = 0, incremento = 8 * ((int)nivell + 1); i < bitsAPoner.Length; j += incremento, i++)//pongo la longitud de los datos y luego los datos
            {
                if (bitsAPoner[i])
                {
                    if (!imgBits[j])
                    {
                        imgBits[j] = true;
                    }
                }
                else
                {
                    if (imgBits[j])
                    {
                        imgBits[j] = false;

                    }
                }


            }

            img.SetBytes(imgBits.ToByteArray());//actualizo la imagen con los datos
        }
        private static byte[] INormalDesXifrat(Bitmap img, NivellXifrat nivell)
        {
            bool[] dadesEnBits;
            try {
                bool[] imgBits = img.GetBytes().ToBits();
                const int BITSLONG = 64;
                bool[] bitsLong = new bool[BITSLONG];

                for (int i = 0, j = 0, incremento = 8 * ((int)nivell + 1); j < BITSLONG; i += incremento, j++)
                    bitsLong[j] = imgBits[i];
                dadesEnBits = new bool[Serializar.ToLong(bitsLong.ToByteArray())];
                for (long i = BITSLONG * 8 * ((int)nivell + 1), final = dadesEnBits.LongLength, j = 0, incremento = 8 * ((int)nivell + 1); j < final; i += incremento, j++)
                    dadesEnBits[j] = imgBits[i];//saco los bits de los datos :)
            }catch { dadesEnBits = new bool[0]; }//si no tiene nada devuelvo byte[0]
            return dadesEnBits.ToByteArray();
        }

    }
}
