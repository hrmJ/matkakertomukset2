
library(SataTapaa)
library(visNetwork)
library(rpart.plot)

set.seed(204)
library(rpart)
library(rpart.plot)
stats <- FormatForStatisticalAnalysis(T)
puu <- rpart(group ~ side + location + dep + pers + pos + tense,stats)
rpart.plot(puu,box.palette=0,extra=100,fallen.leaves=T,type=4)

htmltree <- visTree(puu)
htmltree
visSave(htmltree,file="visualisaatio_puu.html")

library(party)

ct <- ctree(group ~ side + location + dep + pers + pos + tense,stats)

