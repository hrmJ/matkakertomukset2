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
