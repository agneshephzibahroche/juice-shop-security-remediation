/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { resolveSafePath } from '../lib/utils'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file
    const safePath = resolveSafePath('logs/', file)

    if (safePath) {
      res.sendFile(safePath)
    } else {
      res.status(403)
      next(new Error('Invalid file path!'))
    }
  }
}
