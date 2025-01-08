package templates

import "embed"

//go:embed views/*
var TemplatesFS embed.FS

const DownloadListTemp = "views/downloads"
