library(SataTapaa)
library(visNetwork)

#' Luo manuaalinen linkki kahden ryhmän välille yhdistämällä
#' ryhmien keskusnoodit tai vaihtoehtoisesti linkitä
#' suoraan id:llä id:seen tai id:llä ryhmään

Link2Groups <- function(from, to, dashes=FALSE){
    if(!is.numeric(from)){
        from <- test$id[which(test$group==from)][1]
    }
    if(!is.numeric(to)){
        to <- test$id[which(test$group==to)][1]
    }
    hidden <- FALSE
    return(rbind(edges,data.frame(from,to,hidden,dashes)))
}


test <- analysoitu_otanta
test$group[grepl("narratiivi",test$group,ignore.case=T)]  <-  "Narratiivit"
test$sentence <- paste(test$textid,test$sentence)
test$title  <- test$sentence
test$label <- substr(test$sentence,1,18)
test$id <- as.integer(test$textid)
# Etsi joka ryhmän ekat

fromlist <- setNames(lapply(unique(test$group),function(g,te) return(te$id[which(te$group==g)]),te=test),unique(test$group))
from <- c();to <- c()
for(x in fromlist){
    from <- c(from,rep(x[1],length(x)-1))
    to <- c(to,x[c(2:length(x))])
}
edges <- data.frame(from =from, to = to)
edges$hidden <- TRUE
edges$dashes <- FALSE

#Manuaalisia linkityksiä
edges <- Link2Groups("ennakoivien ja predikoivien välimaasto","Ennakoivat")
edges <- Link2Groups("ennakoivien ja predikoivien välimaasto","asuin paikassa x")
edges <- Link2Groups("ennakoivien ja predikoivien välimaasto","Narratiivit")
edges <- Link2Groups("Kontrasti","Suurin osa opiskelijoista")
edges <- Link2Groups("yleistys","asunnon ja asumisen staattinen kuvailu")
edges <- Link2Groups("yleistys","oma kokemus")
edges <- Link2Groups("Suurin osa opiskelijoista","yleistys")
edges <- Link2Groups(688, "asuin paikassa x",TRUE)
edges <- Link2Groups(811, 422, TRUE)
edges <- Link2Groups(76, 263, TRUE)
edges <- Link2Groups(263, 319, TRUE)
edges <- Link2Groups(100, "oma kokemus", TRUE)
edges <- Link2Groups("Yliopisto (maggy) tarjosi","yleistys")
edges <- Link2Groups(61, "Yliopisto (maggy) tarjosi",TRUE)
edges <- Link2Groups(624, "Listamaiset",TRUE)
edges <- Link2Groups(517, "oma kokemus",TRUE)

mynetwork  <- visNetwork(test, edges, width = "100%", height="20cm") %>% 
              visClusteringByGroup(groups = unique(test$group),label="") %>%
             #visLegend() %>%   visLayout(randomSeed = 12, improvedLayout=T) %>%
              visOptions(highlightNearest = FALSE, selectedBy = "side", manipulation = TRUE) %>%
              visPhysics(stabilization = TRUE)
mynetwork

visSave(mynetwork,file="visualisaatio.html")

