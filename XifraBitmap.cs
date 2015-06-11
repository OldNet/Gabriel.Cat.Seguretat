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
    public struct XifratImgNivell
    {
        XifratImg xifrat;
        NivellXifrat nivell;

        public XifratImgNivell(XifratImg xifrat, NivellXifrat nivell)
        {
            this.xifrat = xifrat;
            this.nivell = nivell;
        }

        public XifratImg Xifrat
        {
            get
            {
                return xifrat;
            }

        }

        public NivellXifrat Nivell
        {
            get
            {
                return nivell;
            }
        }
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
                //le mezclo los datos
                case XifratImg.Normal:dades = dades;break;//ejemplo

            }
            IXifra(imgXifrada, xifrat, nivell, dades);
            return imgXifrada;
        }

        public static byte[] Desxifra(this Bitmap img)
        {
            byte[] dades = new byte[0];
            byte[] bytesImg = img.GetBytes();
            XifratImgNivell xifratNivell = img.XifratImgINivell();
            dades = Desxifra(bytesImg, xifratNivell.Nivell);//saco los datos
            switch (xifratNivell.Xifrat)//lo descifro
            {
                //le quito los datos
                case XifratImg.Normal: dades = dades;break;//ejemplo
            }

            return dades;
        }
        public static XifratImgNivell XifratImgINivell(this Bitmap img)
        {
            byte[] bytesImg = img.GetBytes();
            byte[] bytesIdentificador = bytesImg.SubArray(0, 64);
            int[] identificador = DameId(bytesIdentificador);
            XifratImg xifrat = (XifratImg)identificador[0];
            NivellXifrat nivell = (NivellXifrat)identificador[1];
            return new XifratImgNivell(xifrat, nivell);
        }
        private static int[] DameId(byte[] bytesIdentificador)
        {
            bool[] bitsBruts = bytesIdentificador.ToBits();
            bool[] bitsNets = new bool[8 * 8];
            for (int i =0, j = 0; i < bitsBruts.Length; i += 8, j++)
                bitsNets[j] = bitsBruts[i];
            byte[] bytesInts= bitsNets.ToByteArray();
            return new int[] { Serializar.ToInt(bytesInts.SubArray(0,4)), Serializar.ToInt(bytesInts.SubArray(4, 4)) };
        }
        public static long MaxBytesXifrat(this Bitmap bmp,NivellXifrat nivell)
        {
            return bmp.GetBytes().LongLength / (8 * ((int)nivell + 1));
        }

        private static void IXifra(Bitmap img, XifratImg xifrat, NivellXifrat nivell, byte[] dades)
        {
            //pone los bytes en la imagen
            byte[] bytesIdentificador = Serializar.GetBytes((int)xifrat).AfegirValors(Serializar.GetBytes((int)nivell)).ToArray();
            bool[] bitsIdentificador = bytesIdentificador.ToBits();
            byte[] bytesImg = img.GetBytes();
            bool[] imgBits = bytesImg.ToBits();
            const int BITSBYTE = 8;
            byte[] longitud = Serializar.GetBytes(dades.LongLength * BITSBYTE);
            bool[] bitsLong = longitud.ToBits();
            bool[] bitsAPoner =bitsLong.AfegirValors(dades.ToBits()).ToArray();
            if (imgBits.LongLength < bitsAPoner.LongLength * ((int)nivell + 1)+bitsIdentificador.Length*8)
                throw new Exception("La imatge no pot contenir les dades amb el nivell de seguretat posat!");
            for (int j = 0, i = 0, incremento = 8; i < bitsIdentificador.Length; j += incremento, i++)//pongo el identificador
            {
                if (bitsIdentificador[i])
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
            for (int j = bitsIdentificador.Length * 8, i = 0, incremento = 8 * ((int)nivell + 1); i < bitsAPoner.Length; j += incremento, i++)//pongo la longitud de los datos y luego los datos
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
        private static byte[] Desxifra(byte[] imgBytes, NivellXifrat nivell)
        {
            bool[] dadesEnBits;
            try {

                const int INICIO = 64*8;
                bool[] imgBits = imgBytes.ToBits();
                const int BITSLONG = 64;
                bool[] bitsLong = new bool[BITSLONG];

                for (int i = INICIO, j = 0, incremento = 8 * ((int)nivell + 1); j < BITSLONG; i += incremento, j++)
                    bitsLong[j] = imgBits[i];
                dadesEnBits = new bool[Serializar.ToLong(bitsLong.ToByteArray())];
                for (long i = BITSLONG * 8 * ((int)nivell + 1)+INICIO, final = dadesEnBits.LongLength, j = 0, incremento = 8 * ((int)nivell + 1); j < final; i += incremento, j++)
                    dadesEnBits[j] = imgBits[i];//saco los bits de los datos :)
            }catch { dadesEnBits = new bool[0]; }//si no tiene nada devuelvo byte[0]
            return dadesEnBits.ToByteArray();
        }

    }
}
