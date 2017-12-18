# 100 tapaa indikoida topiikkia (100 ways of indicating topic)
A linguistic research paper on indicating topic in the paragraphs of texts written by university students

## R-koodi

Artikkeliin liittyvä R-koodi on tallennettu paketin muodossa (tarkemmin tästä
filosofiasta ks. [Hadley Wickhamin
materiaalit](http://r-pkgs.had.co.nz/intro.html)). 

Paketti on sisällytetty tähän repositorioon. Nopea tapa asentaa se (ja samalla
saada tutkimuksen numeerinen data käyttöön) on käyttää ghit-pakettia.
Toisin sanoen:

```r
    install.packages("ghit")
    library(ghit)
    install_github("hrmJ/100-tapaa-indikoida-topiikkia/rpackage")
```

Kun paketti on asennettu, se otetaan käyttöön jokaisessa R-sessiossa erikseen komentamalla

```r
    library("SataTapaa")
```

## Miten tutkin yksittäisiä tekstejä?

Ota talteen tekstin id, ja avaa netistä osoite

    https://puolukka.uta.fi/jhout/analyzer/index.php?id=

johon loppuun syötät id:n, siis esimerkiksi

    https://puolukka.uta.fi/jhout/analyzer/index.php?id=110

## Aputyökaluja:

- [Markdown pad](http://www.markdownpad.com/download.html) Editori markdown-muotoisen tekstin (raakateksti, josta saa helposti taitettua tekstiä) kirjoittamiseen.

## Lähteisiin viittaaminen

Viitaan tässä lähteeseen [@komppa2012, 98]

Jos ei haluta sukunimeä, niin Komppa [-@komppa2012, 99] 
