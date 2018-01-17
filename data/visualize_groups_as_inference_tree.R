
library(SataTapaa)
library(visNetwork)

set.seed(204)
library(rpart)
#puu <- ctree(group ~ side + location + dep + pers,stats)
stats <- FormatForStatisticalAnalysis()
puu <- rpart(group ~ side + location + dep + pers + pos,stats)
htmltree <- visTree(puu)
htmltree
visSave(htmltree,file="visualisaatio_puu.html")
