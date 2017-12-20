
#install.packages("ghit")
#library(ghit)
#install_github("hrmJ/100-tapaa-indikoida-topiikkia/rpackage")
#install_github("hrmJ/100-tapaa-indikoida-topiikkia/rpackage")
#install.packages("ggthemes")
#install_github("hrmJ/100-tapaa-indikoida-topiikkia/rpackage")
library(SataTapaa)
otannat_analyysiin
View(otannat_analyysiin)
table(otannat_analyysiin$indicator.deprel)
otannat_analyysiin$paragraph[6]
otannat_analyysiin$sentence[6]
history()
savehistory("C:/Users/Ksa/Downloads/satasalamaa.Rhistory")
objektit <- subset(otannat_analyysiin,indicator.deprel=="dobj",select = c("paragraph","sentence"))
