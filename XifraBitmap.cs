using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;

using System.Collections;
using Gabriel.Cat.Extension;

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
        public static Bitmap Xifra(this string text, XifratImg xifrat, NivellXifrat nivell)
        {

            return Serializar.GetBytes(text).Xifra(xifrat, nivell);
        }
        public static Bitmap Xifra(this byte[] dades, XifratImg xifrat, NivellXifrat nivell)
        {
            //por probar, mirar que lo haga bien :)
            //    creo una imagen random que quepa lo que quiero
            int totalBytesImg = dades.Length* ((int)nivell + 1);
            int height = totalBytesImg / 2, width = totalBytesImg - height;
            Bitmap imgRandom=new Bitmap(width,height);
            imgRandom.RandomPixels();
            imgRandom.Xifra(xifrat, nivell, dades);
            return imgRandom;
        }
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
        private static byte[] Desxifra(byte[] imgBytes, NivellXifrat nivell)
        {
            bool[] dadesEnBits;
            try {

                const int BYTESLONG = 8;
                bool[] bitsLong = new bool[BYTESLONG*BYTESLONG];

                for (int i = BYTESLONG, j = 0, incremento = ((int)nivell + 1); j < BYTESLONG; i += incremento, j++)
                    bitsLong[j] = imgBytes[i]%2!=0;
                dadesEnBits = new bool[Serializar.ToLong(bitsLong.ToByteArray())];
                for (long i = BYTESLONG *  ((int)nivell + 1)+ BYTESLONG, final = dadesEnBits.LongLength, j = 0, incremento = ((int)nivell + 1); j < final; i += incremento, j++)
                    dadesEnBits[j] = imgBytes[i] % 2 != 0;//saco los bits de los datos :)
            }
            catch { dadesEnBits = new bool[0]; }//si no tiene nada devuelvo byte[0]
            return dadesEnBits.ToByteArray();
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
            return bmp.GetBytes().LongLength / (((int)nivell + 1));
        }

        private static void IXifra(Bitmap img, XifratImg xifrat, NivellXifrat nivell, byte[] dades)
        {
            //pone los bytes en la imagen
            bool[] bitsIdentificador = Serializar.GetBytes((int)xifrat).AfegirValors(Serializar.GetBytes((int)nivell)).AfegirValors(Serializar.GetBytes(dades.Length)).ToBits();
            bool[] bitsAPoner = dades.ToBits();
              
            if (img.LengthBytes() < (bitsAPoner.LongLength +bitsIdentificador.Length)*((int)nivell + 1))
                throw new Exception("La imatge no pot contenir les dades amb el nivell de seguretat posat!");
            unsafe
            {
                img.TrataBytes((MetodoTratarBytePointer)((imgBytes) =>
                {
                    int longitudImg = img.LengthBytes();
                    int auxByte = 0;
                    for (int i = 0; i < bitsIdentificador.Length; i++)//pongo el identificador
                {
                        if (bitsIdentificador[i])
                        {
                            if (imgBytes[i]%2==0)
                            {
                             auxByte= imgBytes[i];
                                //tiene que ser true
                                if(auxByte%2==0)
                                {
                                    auxByte++;
                                    imgBytes[i] =(byte)auxByte;
                                }
                            }
                        }
                        else
                        {
                            if (imgBytes[i] % 2 != 0)
                            {
                                auxByte = imgBytes[i];
                                //tiene que ser false
                                if (auxByte % 2 != 0)
                                {
                                    auxByte--;
                                    imgBytes[i] = (byte)auxByte;
                                }
                            }
                        }


                    }
                    for (int j = bitsIdentificador.Length, i = 0, incremento = ((int)nivell + 1); i < bitsAPoner.Length; j += incremento, i++)//pongo la longitud de los datos y luego los datos
                {
                        if (bitsAPoner[i])
                        {
                            if (imgBytes[j] % 2 != 0)
                            {
                                auxByte = imgBytes[j];
                                //tiene que ser false
                                if (auxByte % 2 == 0)
                                {
                                    auxByte++;
                                    imgBytes[j] = (byte)auxByte;
                                }
                            }
                        }
                        else
                        {
                            auxByte = imgBytes[j];
                            //tiene que ser false
                            if (auxByte % 2 != 0)
                            {
                                auxByte--;
                                imgBytes[j] = (byte)auxByte;
                            }
                        }
                    }


                    }
                ));
            }

        }


    }
}
