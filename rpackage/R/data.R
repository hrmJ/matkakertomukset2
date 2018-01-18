#' Pari yleistilastoa koko aineistosta
#'
#' Ennen kaikkea kaikkien tekstien määrä (niidenkin, joissa ei asumiskpl)
#'
"overall_stats"

#' Ristiinannotoinnin tulokset kappaleittain
#'
#' Tässä dataframessa ovat ne 322 kappaletta, jotka kirjoittajat molemmat tahoillaan annotoivat siten, että kumpikin merkitsi joka kappaleeseen sen aiheen, jota kappale kirjoittajan mielestä edusti.
#'
"ristiin_annotointi"


#' Metatiedot ryhmistä
#'
#' Tässä dataframessa ovat tarkemmat tiedot eri ryhmistä
#'
"groups.meta"

#' Analysoitu data satunnaisotannan jälkeen. 
#'
#' Tässä dataframessa ovat tapaukset, jotka on jo ryhmitelty satunnaisotannan perusteella tehdyn laadullisen analyysin tuloksena.
#'
#' @format A data frame with the following structure:
#' \describe{
#'   \item{textid}{Tekstin id}
#'   \item{previous_paragraph}{Edellisen kappaleen teksti}
#'   \item{sentence}{Virke, jossa indikaattori on}
#'   ...
#' }
"analysoitu_otanta"

#' Ensimmäistä asumista käsittelevää kappaletta edeltävä kappale ja tekstin id
#'
#' Tällä vain täydennetään jo olemassaolevaa dataa
#'
#' @format A data frame with the following structure:
#' \describe{
#'   \item{textid}{Tekstin id}
#'   \item{previous_paragraph}{Edellisen kappaleen teksti}
#'   ...
#' }
"previous_pars"

#' Ensimmäistä asumista käsittelevää kappaletta edeltävä välitosikko ja tekstin id
#'
#' Tällä vain täydennetään jo olemassaolevaa dataa
#'
#' @format A data frame with the following structure:
#' \describe{
#'   \item{textid}{Tekstin id}
#'   \item{chaptertitle}{Edellisen kappaleen väliotsikko}
#'   ...
#' }
"chaptertitles"



#' Dataframe, jossa käsitellyt satunnaisotantatapaukset. 
#'
#' Näihin siis merkitty jo, mikä manuaalisen ryhmittelyn tuloksena
#' määritelty ryhmä on kyseessä.
#'
#' @format A data frame with the following structure:
#' \describe{
#'   \item{textid}{Tekstin id}
#'   \item{chaptertitle}{Edellisen kappaleen väliotsikko}
#'   ...
#' }
"chaptertitles"
