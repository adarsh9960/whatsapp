/**
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import express from "express";
import { decryptRequest, encryptResponse, FlowEndpointException } from "./encryption.js";
import { getNextScreen } from "./flow.js";
import crypto from "crypto";

const app = express();

app.use(
  express.json({
    // store the raw request body to use it for signature verification
    verify: (req, res, buf, encoding) => {
      req.rawBody = buf?.toString(encoding || "utf8");
    },
  }),
);

const { APP_SECRET, PRIVATE_KEY, PASSPHRASE = "", PORT = "3000" } = process.env;

/*
Example:
```-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,487167BB3A87FAFE

+g3xiHa0U5NwUkjIpMME+nIImyHXfZNVYZL+FY4JKsymolt8m77mLcPOXkn2Z69O
DnDXInEaMKyXqoBjegv9RZxBDGGRC2eMTHrkfRMHk168YhnLWok1oYZxZ85HLkbU
5jgDvNhbQldSBMl7w4/izhvcXCDZAq44qP9aN00vQh9UdLKb5zuLroUMDFiVZND7
3pYI0bEM8SEqGAplVyD35i7tI77lysAJfBMvTaso6yPr7bXauR0ZJGdlvRl+JIzy
eKdipEfDjpxYdQ+5C6I4BzIY/bwfuQXSqxFxGcslb+ZCWBmyoZ7S/4FuEuJsq2Ys
Pi4QvhvetYgbuzGaRemTsxlpRi0J5xdWF1qgqNBAOU/qbGxjSKM2UdQoJsYswQV3
3r9FpBS+H62u+nJrjUSFuLvhIzGe1egPXmdcrEKMFJgteAzh0nSXDIyp5DyK2ad2
CJjKr7iMqdcvI4eCEcs/n0+/HcKeuA8Y2HxWVwT0DMVM93ULB3XZDSnjxqRrFIZw
i1ALrUKi2eovwLkpfI6DfJBj94/FhN65yb6+kq7TogSBN4/yi1eiaM+KLPzxZfZ9
CnT/95IszR7n3dUeIR085k2S5JRSmlNtS+cMaRrRbAAr8c+/oskjwUJZGj2qMfAI
6AqlB271ndX+z/XY5sr7sUeWpBlVK7NjAudh4lxEfoYfF+ClhcFTyzTn1lHxNjkT
7UdqYw52iTp6jrFeIbVRgLNbJifVx2BvLXM52HbuJktzWa4fPmCfqPnWa7bDTER1
mAaH8tr/3yX4o3W0zj0f+ZkSZ+FWN4vYSCmBp2AggVnMqIaD5BweamWNC8XbHz6H
/RoHHlezqb0GoGfUDLCh7p6FJEHvwPTMVeRvufnPqJV3WIB2aSwBwsS/OkZosB0w
xTZ1sLKJpkSC6E9BgcVBd2dGczBuIYdAs/ESU11LaD3pVsD1Bdt3FNuMhhJ8vC3N
rcf0PkYkZllOOqgHkctlB9L/8O2+F6OqqKXxQPb3obkXgoTTSytEtUa9QX9ZgHbQ
tTyqzKt5qfyGh2Gn7GKG0bnfyqkYgoaOWyFUm2jcAthB25fxbbcBmw9DZFgwgwPI
qGUifhtMVtCmCbQLdZCWJwXGAD7qUXuQbEw9xfKfftWhpELsX5Sx9gASPtY7xMXu
FOuNFoAM6A05z/I7PdbBdWI+leBPxVcCuQLOgOkM9IBXMkRBN3dQPzySP2Eq1lpr
xfDFhfkg8Jz70/bwNtsXy5JvrPDmedGeTrL/WZbBTzbbWjbNCJfGA6z5kYBeSN+V
3xMaBT1VOGbfJImLOHILtPvdt2g4VDY67jV3wk1sgZ0EXyLEAL/r0BoNEy0P+gN/
dPLgbP6MssZTnhzxaXll+C7dKMsg5vh6erAyHlWOiSzkml8/H+2lcMmiVth2q+gL
D1z9yOxJZ2oPykJ2diuFlb4xZuq09Bl5YSknKS+ZikwgWHS3NGmR1hLPItXV7yR9
j2S9qPyezSW45ZtOeSvMnnDejNB/Ys3iPlaZUNONB/BRr6zp8IKCvCHYll6GeFNw
ZdmQnLUGKOQod2w6Un7aPlwbD2j9fo5Mr6oHudgxD0ixtAnnAFtYGg==
-----END RSA PRIVATE KEY-----```
*/

app.post("/", async (req, res) => {
  if (!PRIVATE_KEY) {
    throw new Error(
      'Private key is empty. Please check your env variable "PRIVATE_KEY".'
    );
  }

  if(!isRequestSignatureValid(req)) {
    // Return status code 432 if request signature does not match.
    // To learn more about return error codes visit: https://developers.facebook.com/docs/whatsapp/flows/reference/error-codes#endpoint_error_codes
    return res.status(432).send();
  }

  let decryptedRequest = null;
  try {
    decryptedRequest = decryptRequest(req.body, PRIVATE_KEY, PASSPHRASE);
  } catch (err) {
    console.error(err);
    if (err instanceof FlowEndpointException) {
      return res.status(err.statusCode).send();
    }
    return res.status(500).send();
  }

  const { aesKeyBuffer, initialVectorBuffer, decryptedBody } = decryptedRequest;
  console.log("💬 Decrypted Request:", decryptedBody);

  // TODO: Uncomment this block and add your flow token validation logic.
  // If the flow token becomes invalid, return HTTP code 427 to disable the flow and show the message in `error_msg` to the user
  // Refer to the docs for details https://developers.facebook.com/docs/whatsapp/flows/reference/error-codes#endpoint_error_codes

  /*
  if (!isValidFlowToken(decryptedBody.flow_token)) {
    const error_response = {
      error_msg: `The message is no longer available`,
    };
    return res
      .status(427)
      .send(
        encryptResponse(error_response, aesKeyBuffer, initialVectorBuffer)
      );
  }
  */

  const screenResponse = await getNextScreen(decryptedBody);
  console.log("👉 Response to Encrypt:", screenResponse);

  res.send(encryptResponse(screenResponse, aesKeyBuffer, initialVectorBuffer));
});

app.get("/", (req, res) => {
  res.send(`<pre>Nothing to see here.
Checkout README.md to start.</pre>`);
});

app.listen(PORT, () => {
  console.log(`Server is listening on port: ${PORT}`);
});

function isRequestSignatureValid(req) {
  if(!APP_SECRET) {
    console.warn("App Secret is not set up. Please Add your app secret in /.env file to check for request validation");
    return true;
  }

  const signatureHeader = req.get("x-hub-signature-256");
  const signatureBuffer = Buffer.from(signatureHeader.replace("sha256=", ""), "utf-8");

  const hmac = crypto.createHmac("sha256", APP_SECRET);
  const digestString = hmac.update(req.rawBody).digest('hex');
  const digestBuffer = Buffer.from(digestString, "utf-8");

  if ( !crypto.timingSafeEqual(digestBuffer, signatureBuffer)) {
    console.error("Error: Request Signature did not match");
    return false;
  }
  return true;
}
