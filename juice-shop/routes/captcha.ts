/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { CaptchaModel } from '../models/captcha'

// SECURITY: previously built an expression string and eval()'d it. The operands here are always
// server-generated random numbers, not user input, but `eval` on any non-literal string is a risky
// pattern regardless — this computes the same three-term expression without executing code.
function apply (x: number, operator: string, y: number): number {
  switch (operator) {
    case '*': return x * y
    case '+': return x + y
    case '-': return x - y
    default: throw new Error(`Unsupported operator: ${operator}`)
  }
}

function evaluateExpression (a: number, op1: string, b: number, op2: string, c: number): number {
  // preserves standard operator precedence (* before +/-) to match the displayed expression string
  if (op1 === '*' || op2 !== '*') {
    return apply(apply(a, op1, b), op2, c)
  }
  return apply(a, op1, apply(b, op2, c))
}

export function captchas () {
  return async (req: Request, res: Response) => {
    const captchaId = req.app.locals.captchaId++
    const operators = ['*', '+', '-']

    const firstTerm = Math.floor((Math.random() * 10) + 1)
    const secondTerm = Math.floor((Math.random() * 10) + 1)
    const thirdTerm = Math.floor((Math.random() * 10) + 1)

    const firstOperator = operators[Math.floor((Math.random() * 3))]
    const secondOperator = operators[Math.floor((Math.random() * 3))]

    const expression = firstTerm.toString() + firstOperator + secondTerm.toString() + secondOperator + thirdTerm.toString()
    const answer = evaluateExpression(firstTerm, firstOperator, secondTerm, secondOperator, thirdTerm).toString()

    const captcha = {
      captchaId,
      captcha: expression,
      answer
    }
    const captchaInstance = CaptchaModel.build(captcha)
    await captchaInstance.save()
    res.json(captcha)
  }
}

export const verifyCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const captcha = await CaptchaModel.findOne({ where: { captchaId: req.body.captchaId } })
    if ((captcha != null) && req.body.captcha === captcha.answer) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    next(error)
  }
}
