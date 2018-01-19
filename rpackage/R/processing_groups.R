
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
#' @param numericalgroups käytetäänkö ryhmien niminä numeroita
#' @export

FormatForStatisticalAnalysis <- function(numericalgroups=F){


    stats <- subset(analysoitu_otanta,select=c("group","indicator.deprel","headverb_person","side","textid"))

    if(numericalgroups){
        ex.ids <- c(286, 42, 314, 699, 317, 107, 341,557,272,498,732,390,298)
        esim <- setNames(lapply(ex.ids,function(x)MoreInfo(x)),groups.meta$Nimi)
        totals <- sort(sapply(esim,function(x)x$total),dec=T)
        stats$group <- sapply(stats$group,function(x)which(names(totals)==x))
    } else{
        stats$group <- stri_trans_tolower(gsub("\\s+","",substr(stats$group,1,5)))
        stats$group[stats$group=="Selke"] <- "narr"
    }

    #Muotoillaan vähän sijaintitilastoja
    stats$location <- as.factor(sapply(stats$textid,function(tid){
                                            loc = otannat_analyysiin$indicatorloc[otannat_analyysiin$textid == tid]
                                            return(ifelse(loc==1,"alku","muu"))
    }))

    #Dep:in uudelleen määrittely
    stats$dep  <- stats$indicator.deprel
    stats$dep[stats$dep %in% c("nmod:gobj", "nmod:poss")] <- "nmod:x"
    stats$dep[stats$dep %in% c("nsubj", "nsubj:cop")] <- "subj"
    stats$dep[stats$dep %in% c("nsubj", "nsubj:cop")] <- "subj"

    #Aikamuoto

    stats$tense <- "?"
    stats$feat <- sapply(stats$textid,function(x)withindicator$headverb_feat[withindicator$textid==x])
    stats$tense[grepl("Tense=Past",stats$feat)] <- "imp"
    stats$tense[grepl("Tense=Pres",stats$feat)] <- "prees"
    stats$sent <- analysoitu_otanta$sentence
    stats$tense[grepl("PartForm=Past\\|VerbForm=Part",stats$feat)] <- "pl.perf/perf"

    sent <- c( "Kv. koordinaattori Maggy oli suuri apu asuntoa etsittäessä.", "Asuntoa voi hakea BNU nettijärjestelmän kautta, johon saa ohjeet hyväksymispaketin kanssa.", "Asuntoa minun ei tarvinnut hankkia.", "Asuntoa oli hyvin vaikea saada vapailta markkinoilta etänä, sillä kukaan ei halunnut vuokrata minulle huonetta ainoastaan neljäksi kuukaudeksi tapaamatta kasvotusten.", "Vaihtoon haettaessa hain myös asuntolapaikkaa, ja sain valita itse mieluisimman asuntolan( tästä myöhemmin lisää) .", "Sairastelun lisäksi vaihtovuoden negatiivisin asia oli ehdottomasti asuminen.", "Hain asuntoa vaihto-opiskelijoille asuntoja järjestävän OeADin kautta varsin myöhään, kesäkuun puolivälissä.", "Asuminen, tai siis lähinnä asunnon hankkiminen, oli varmaankin vaihdon hankalin juttu.", "Asuminen: Vuokrasin huoneen yliopiston omista asuntoloista.", "Jos asunnonhausta haluaa päästä helpolla, voi asuntoa hakea Studentenwerk Potsdamin kautta.", "Mielestäni asuntolassa asuminen oli ihan viihtyisää.", "Sitten pari sanaa asumisesta.", "Asunnon hankkiminen oli ainoa vähänkään hankala tai työläs tehtävä ennen lähtöä tapahtuneista etukäteisjärjestelyistä, kaikki muu oli hyvin helppoa.", "Asunnon hankkiminen oli helppoa vaihtareille tarkoitetun StayInAthens -järjestön kautta.", "Asunnon hankkiminen Kööpenhaminassa on erittäin hankalaa ja vuokrataso on hyvin korkea.", "Kaikkein vaikein asia oli asunnon löytäminen.", "Asunnon saaminen Uppsalassa ei ole itsestäänselvyys, joten kannattaa ottaa asunto, jota yliopisto tarjoaa.", "Asunnon hakeminen oli todella helppoa.", "Sitten asunnon hankkiminen.", "Asumisen osalta vaihtoehdot ovat asuntola ja yksityinen vuokranantaja, joilla kummallakin on puolensa.", "Jos halusi saada paikallisen opiskelija-asuntosäätiön asunnon, piti tehdä online-hakemus suoraan kyseiselle taholle( Studentenwerk) .", "Ensimmäinen vinkkini asunnon etsintään: OLKAA AJOISSA LIIKKEELLÄ!", "Asumisratkaisumme oli kaupungin reunalla pellon laidalla sijaitseva opiskelija-asuntola Avant-Garde, jossa jokaisella oli yksiö vessalla ja suihkulla.", "Asuminen Riossa ei ole kovinkaan edullista, eikä Ibmec tarjoa majoitusvaihtoehtoja opiskelijoille.", "Asuminen Tokiossa on aika kallista.", "Asuminen pääkampuksen asuntolassa oli edullista, ja Kelan opintotuki ulkomaille riitti muutenkin mainiosti kattamaan käytännössä kaikki kuluni Moskovassa.", "Asumisjärjestelyt olivat vaihdon aikana paljon puhuttu sirkus, kun jatkuvasti joku muutti paikasta toiseen erinäisistä syistä.", "Ulkomaisille opiskelijoille tarkoitettu asuntola on vain kolme vuotta vanha ja täten melko moderni.", "Se oli kuitenkin erittäin hankalaa, sillä monet olivat jo syksyllä muuttaneet yhteen ja enää oli jäljellä vain kalliimmat opiskelija-asuntolat.", "Koska kurssini olivat kaikki yliopiston keskustakampuksella ja yliopiston asuntola kahdeksan kilometrin päässä laitakaupungin Sart Tilman–kampuksella, oli järkevintä etsiä asunto yksityiseltä vuokranantajalta.", "Asuntolamme on uusi, rakennettu 2013 vuonna.", "Asuntola on 3 asemaa Ikebukurosta, yhdestä Tokion isoimmista keskustoista, ja yliopisto vielä 2 asemaa Ikebukurosta.", "Kielikurssin ajan asuin Maaülikoolin asuntolassa, joka on hieman kauempana keskustasta( kävelyetäisyydellä silti) .", "Olin hyvin onnekas ja löysin pitkän etsinnän jälkeen itselleni kimppakämpän Caenin keskustasta, missä asuin kahden ranskalaisen lääkisopiskelijan kanssa.")
    tense <- c( "imp", "prees", "imp", "imp", "imp", "imp", "imp", "imp", "imp", "prees", "imp", "--", "imp", "imp", "prees", "imp", "prees", "imp", "--", "prees", "imp", "--", "imp", "prees", "prees", "imp", "imp", "prees", "imp", "imp", "imp", "prees", "imp", "imp")
    for(idx in c(1:length(sent))){
        s  <- sent[idx]
        t  <- tense[idx]
        stats$tense[stats$sent==s] <- t
    }
    stats$tense[grepl("Namurin vahvuuksia",stats$sent)] <- "prees"
    stats$tense[grepl("Minulla ei ollut asuntoa valmiina,",stats$sent)] <- "imp"
    stats$tense[grepl("Lähtiessäni Berliiniä kohti",stats$sent)] <- "imp"
    stats$tense[grepl("Asuntoa minulla ei ollut valmiiksi",stats$sent)] <- "imp"
    stats$tense[grepl("Asuntoa minulla ei vielä ennen Brysseliin saapumista ollut",stats$sent)] <- "imp"
    stats$tense[grepl("Itse en saanut asuntoa Studierendenwerkiltä, joten jouduin etsimään s",stats$sent)] <- "imp"
    stats$tense[grepl("Asuminen Kentissä on järjestetty",stats$sent)] <- "prees"


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


