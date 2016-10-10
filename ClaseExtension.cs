using Gabriel.Cat.Seguretat;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Gabriel.Cat.Extension
{
    public delegate T ObjetoRandom<T>();
    public static class ClaseExtension
    {
        /// <summary>
        /// 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="lista">no puede contener la marcaFin ni el valor por defecto</param>
        /// <param name="metodoObjetoRandom">el objeto no puede ser el valor por defecto del tipo ya que se usa</param>
        /// <param name="marcaFin"></param>
        /// <param name="inicioMatriz"></param>
        /// <param name="password"></param>
        /// <param name="nivel"></param>
        /// <returns></returns>
        public static IEnumerable<T> Oculta<T>(this IEnumerable<T> lista, ObjetoRandom<T> metodoObjetoRandom, T marcaFin, Point inicioMatriz, string password, LevelEncrypt nivel)
        {
            if (metodoObjetoRandom == null || marcaFin.Equals(default(T)) || String.IsNullOrEmpty(password)||lista.Contains(marcaFin)||lista.Contains(default(T)))
                throw new ArgumentException("Hay argumentos no validos!");
            const double MULTIPLICADOR = 13 / 11;
            Vector vector = new Vector(0, 0, inicioMatriz.X, inicioMatriz.Y);
            Pila<T> pilaObjs = new Pila<T>();
            T[,] matriz;
            pilaObjs.Push(marcaFin);
            foreach (T obj in lista)
            {
                pilaObjs.Push(obj);
                for (int i = 0, f = (int)nivel + 1; i < f; i++)
                    pilaObjs.Push(metodoObjetoRandom());
            }
            matriz = new T[(Convert.ToInt32(Math.Sqrt(pilaObjs.Count) * MULTIPLICADOR)), (Convert.ToInt32(Math.Sqrt(pilaObjs.Count) * MULTIPLICADOR))];
            //codigo para perder los datos
            while (!pilaObjs.Empty)
            {
                vector = matriz.GetVector((int)password[vector.FinX * vector.FinY], vector.FinX, vector.FinY);
                matriz.Recorrer(vector, (ContinuaTratandoObjeto<T>)((obj) =>
                {
                    if (obj.Equals(default(T)))//salto a los diferentes porque son valores puestos :D
                        obj = pilaObjs.Pop();
                    return new ContinuaTratando<T>() { Objeto = obj, Continua = !pilaObjs.Empty };

                }));
            }
            //relleno los huecos los que tienen el valor por defecto
            for (int y = 0, yFin = matriz.GetLength(DimensionMatriz.Y), xFin = matriz.GetLength(DimensionMatriz.X); y < yFin; y++)
                for (int x = 0; x < xFin; x++)
                    if (matriz[x, y].Equals(default(T)))
                        matriz[x, y] = metodoObjetoRandom();
            return matriz.OfType<T>();
        }
        public static IEnumerable<T> Desoculta<T>(this IEnumerable<T> lista, ObjetoRandom<T> metodoObjetoRandom, T marcaFin, Point inicioMatriz, string password, LevelEncrypt nivel)
        {
            if (metodoObjetoRandom == null || marcaFin.Equals(default(T)) || String.IsNullOrEmpty(password) || lista.Contains(marcaFin) || lista.Contains(default(T)))
                throw new ArgumentException("Hay argumentos no validos!");
            Vector vector = new Vector(0, 0, inicioMatriz.X, inicioMatriz.Y);
            Llista<T> pilaObjs = new Llista<T>();
            T[,] matriz;
            pilaObjs.Afegir(default(T));
            matriz = new T[(Convert.ToInt32(Math.Sqrt(pilaObjs.Count))), (Convert.ToInt32(Math.Sqrt(pilaObjs.Count)))];
            //codigo para perder los datos
            while (!pilaObjs[pilaObjs.Count-1].Equals(marcaFin))
            {
                vector = matriz.GetVector((int)password[vector.FinX* vector.FinY], vector.FinX, vector.FinY);
                matriz.Recorrer(vector, (ContinuaTratandoObjeto<T>)((obj) =>
                {
                    if (!obj.Equals(default(T)))//salto a los diferentes porque son valores puestos :D
                       pilaObjs.Afegir(obj);
                    return new ContinuaTratando<T>() { Objeto = default(T), Continua = !obj.Equals(marcaFin) };

                }));
            }
            pilaObjs.Pop();//quito default centinela
            pilaObjs.Elimina(pilaObjs.Count - 1);//quito marcafin

            return pilaObjs;
        }
    }
}
