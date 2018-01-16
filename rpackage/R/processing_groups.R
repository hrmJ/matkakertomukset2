
#' Hae data ryhmistä yaml-tiedostojen perusteella
#' @importFrom yaml yaml.load_file
#' @export

GetGroupsFromYaml <- function(otanta){

    # ryhmien nimet
    grouplist <- setNames(lapply(list.files("data/groups/"),function(x)return(yaml.load_file(paste0("data/groups/",x)))),list.files("data/groups/"))
    cc<-lapply(grouplist,function(x)return(list(Nimi=x$Nimi,Kuvaus=x$Kuvaus,"Yläotsikko"=x$ylaotsikko)))
    groups.meta <- as.data.frame(t(as.data.frame(do.call(cbind,cc))))
    for(cname in colnames(groups.meta)){
        groups.meta[[cname]] <- unlist(groups.meta[[cname]])
    }
    # ryhmien numeron merkkaaminen dataframeen
    otanta$group  <- ""
    otanta$side  <- ""
    for(g in grouplist){
        for (textid in g$textid){
          otanta$group[otanta$textid==textid$id] <- g$Nimi
          otanta$side[otanta$textid==textid$id] <- textid$side
        }
    }
    return(otanta)
}


#' Antaa nopeasti tietoa jonkin klusterin ominaisuuksista
#' @param textid esimerkin teksti-id
#' @export

MoreInfo <- function(textid){
    info  <- GetInfo(textid)
    ss <- subset(analysoitu_otanta, group==info$group)
    siteet <- table(ss$side)
    return(list(sentence = info$sentence,
                group=info$group,
                total=nrow(ss),
                otsikkosuhde = paste(round(siteet["otsikko"]/nrow(ss)*100,2),"%"),
                otsikoita = unname(siteet["otsikko"]),
                suht.koko = paste(fn(100*nrow(ss)/nrow(analysoitu_otanta)),"%")
                )
                )
}
