#' refs
#' @export

references <- new.env()
references$tab <- list(labels=c(),caption.prefix="Taulukko")
references$fig <- list(labels=c(),caption.prefix="Kuvio")
references$def <- list(labels=c(),caption.prefix="Määritelmä")
references$hyp <- list(labels=c(),caption.prefix="Hypoteesi")
references$mat <- list(labels=c(),caption.prefix="Matriisi")


#' Tyhjentää kaikki taulukoihin ja kuvioihin ym. viittaavat listat
#' @export
ClearReferences <- function(){
    for(name in names(references)){
        references[[name]]$labels=c()
    }
}


#'  Referencing tables, figures etc in the document.
#' 
#' @param reftype what we are referencing e.g. "tab", "fig"
#' @param label identifier for this particular instance
#' @param caption the caption (omit when only referencing)
#' @return  the reference for the table, figure etc OR the caption, depending on the input parameters
#' 
#' @export
#' 
#' @examples
#' 
#' #1. Creating a caption for a figure
#' Ref('fig','ff_flower', 'A diagram of flowers')
#' 
#' #2. Creating a caption for a table
#' Ref('fig','tt_letters', 'A table of letters in text A')
#' 
#' Notice that a good practice is to start labels of one type
#' with a prefix like tt_ for tables. This makes it easier to use
#' autocomplete functions in text editors. The prefixes are not, however,
#' compulsory, Ref('table','just.a.label','A table of letters in text A') will
#' do just as well.
#' 
#'  #3. Referencing:
#' Look at figure Ref('fig','tt_letters'), which...
#' 

Ref <- function(reftype=character(), label=character(), caption=character()) {
    rval <- ""
    #katso, onko tätä taulukon nimeä tallennettu kaikkien taulukoiden listaan
    no <- which(references[[reftype]]$labels == label)
    #jos ei ole tallennettu ja tämä on se kohta, jossa taulukko oikeasti sijaitsee (taulukon otsikko on myös annettu)
    if (!missing(caption)) {
        if (length(no) == 0 & !missing(caption)) {
            #lisätään tässä tapauksessa taulukon nimi nimien listaan viimeiseksi
            references[[reftype]]$labels <- c(references[[reftype]]$labels, label)
        }
        no <- which(references[[reftype]]$labels == label)
        #Tulostetaan taulukon otsikko
        paste0(references[[reftype]]$caption.prefix, " ", no, ": ", caption)
        rval <- paste0(references[[reftype]]$caption.prefix, " ", no, ": ", caption)
    }
    else if(missing(caption) & length(no) > 0){
        #tekstinsisäinen viittaus
        paste0(no)
        rval <- paste0(no)
    }
    return(rval)
}
