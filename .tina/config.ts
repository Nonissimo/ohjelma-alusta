import { defineConfig } from "tinacms";

// Your hosting provider likely exposes this as an environment variable
const branch = process.env.HEAD || process.env.VERCEL_GIT_COMMIT_REF || "main";

export default defineConfig({
  branch,
  clientId: null, // Get this from tina.io
  token: null, // Get this from tina.io
  build: {
    outputFolder: "admin",
    publicFolder: "static",
  },
  media: {
    tina: {
      mediaRoot: "",
      publicFolder: "static",
    },
  },
  schema: {
    collections: [
      {
        name: "ohjelma",
        label: "Ohjelmat",
        path: "content/ohjelmat",
        fields: [
          {
            type: "string",
            name: "title",
            label: "Otsikko",
            isTitle: true,
            required: true,
          },
          {
            type: "number",
            name: "year",
            label: "Vuosi",
          },
          {
            type: "string",
            name: "type",
            label: "Ohjelman tyyppi",
          },
          {
            type: "string",
            name: "hyvaksyja",
            label: "Hyväksyjä",
            options: [{
              value: 'Puoluevaltuusto',
              label: 'Puoluevaltuusto'
            }, {
              value: 'Puoluehallitus',
              label: 'Puoluehallitus'
            }, {
              value: 'Puoluekokous',
              label: 'Puoluekokous'
            }, {
              value: 'Työryhmä',
              label: 'Työryhmä'
            }, {
              value: 'Eduskuntaryhmä',
              label: 'Eduskuntaryhmä'
            }]
          },
          {
            type: "string",
            name: "voimassa",
            label: "Voimassaolo",
            options: [{
              value: 'vihrea',
              label: 'Vihreä: voimassa'
            }, {
              value: 'keltainen',
              label: 'Keltainen: voimassa varauksin'
            }, {
              value: 'punainen',
              label: 'Punainen: rauennut'
            }]
          },
          {
            type: "string",
            name: "disclaimer",
            label: "Varauma merkittäväksi ohjelman oheen"
          },
          {
            type: "string",
            name: "sektori",
            label: "Politiikkasektori",
            list: true,
            options: [{
              value: 'talous',
              label: 'Talouspolitiikka'
            }, {
              value: 'ympäristö',
              label: 'Ympäristöpolitiikka'
            }, {
              value: 'koulutus',
              label: 'Koulutuspolitiikka'
            }, {
              value: 'tiede',
              label: 'Tiedepolitiikka'
            }, {
              value: 'kulttuuri',
              label: 'Kulttuuripolitiikka'
            }, {
              value: 'alue',
              label: 'Aluepolitiikka'
            }, {
              value: 'maatalous',
              label: 'Maatalouspolitiikka'
            }]
          },
          {
            type: "rich-text",
            name: "body",
            label: "Teksti",
            isBody: true,
          },
        ],
      },
    ],
  },
});
