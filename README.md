# Kyber
Código referente al trabajo titulado "Implementación del criptosistema postcuántico CRYSTALS-Kyber y análisis de sus trazas de consumo de potencia para la ejecución de ataques por canal lateral"

En este repositorio aparecen dos carpetas:
  - kyber\_notebook: contiene los cuadernos de jupyter notebook utilizados para la obtención y el análisis de las trazas, y datos relevantes para el procedimiento.
    - docs: carpeta con documentos relativos a los datos obtenidos.
    - traces: carpeta con imágenes y valores de trazas obtenidas a lo largo del desarrollo. Sus subcarpetas indican el algoritmo del que provienen las trazas.
    - variables: carpeta en la que se guardan las variables de entorno que se introducen en el DUT.
    - exec: archivo generado automáticamente para la ejecución del código en jupyter notebook.
    - fft\_examples-ipynb: ejemplo de transformada de Fourier sobre una función sinusoidal.
    - kyber.ipynb: archivo que contiene todo el desarrollo del trabajo.
    - temp\_variable\_generator: archivo generador de las variables temporales. Las variables generadas son guardadas en la carpeta variables.
    - ttest\_graph.ipynb: archivo que contiene el gráfico del ttest generado en la Figura 3.4.
    - variable\_generator: archivo generador de las variables. Las variables generadas son guardadas en la carpeta variables.
  - kyber: contiene el código en C que forma parte del firmware del DUT.
    - objdir-CWLITEARM: carpeta con los archivos generados por el archivo makefile para la correcta compilación del programa.
    - makefile: archivo compilador del programa.
    - rng.c: archivo con la implementación de randombytes para Chipwhisperer.
    - simpleserial-kyber.c: archivo principal y orquestador del programa.
    - simpleserial-kyber-CWLITEARM.hex: código compilado del programa en formato hexadecimal.
    - variable\_generator: archivo generador de las variables. Las variables generadas son guardadas en la carpeta variables.
    - El resto de los archivos que aparecen en esta carpeta, o bien forman parte del código oficial de CRYSTALS-Kyber, o bien son archivos generados en el proceso de compilación.
