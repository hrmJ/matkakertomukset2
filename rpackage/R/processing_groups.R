
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


#' Muotoilee analysoitua dataa niin, että sitä on helppo käyttää tilastollisessa analyysissa
#' 
#' @importFrom stringi stri_trans_tolower
#' @export

FormatForStatisticalAnalysis <- function(){

    stats <- subset(analysoitu_otanta,select=c("group","indicator.deprel","headverb_person","side","textid"))
    stats$group <- stri_trans_tolower(gsub("\\s+","",substr(stats$group,1,5)))
    stats$group[stats$group=="Selke"] <- "narr"


    #Muotoillaan vähän sijaintitilastoja
    stats$location <- as.factor(sapply(stats$textid,function(tid){
                                            loc = otannat_analyysiin$indicatorloc[otannat_analyysiin$textid == tid]
                                            return(ifelse(loc==1,"alku","muu"))
    }))
    stats$dep  <- stats$indicator.deprel
    stats$pers  <- stats$headverb_person
    #TODO: fix this
    stats$side[stats$side=="check"] <- "x"
    stats$side[stats$side=="orient"] <- "edellinen"
    stats <- stats[,-which(names(stats) %in%c("headverb_person","indicator.deprel"))]

    #Muotoillaan vähän sanaluokkatilastoja
    stats$pos <- as.factor(sapply(stats$textid,function(tid){
                                            f = otannat_analyysiin$indicatorword_feat[otannat_analyysiin$textid == tid]
                                            if(grepl("(Inf|Minen)",f)){
                                                return("inf/minen")
                                            } else if(grepl("Mood",f)) {
                                                return("fin")
                                            } else if(grepl("Case",f)) {
                                                return("NP")
                                            } }))

    stats$pers[grepl("1",stats$pers)] <- "1.p."
    stats$pers[!grepl("1",stats$pers)] <- "muu"

    stats <- stats[,-which(names(stats)=="textid")]
    for(n in names(stats)){
        stats[[n]] <- as.factor(stats[[n]])
    }

    return(stats)

}

