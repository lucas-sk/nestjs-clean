import { Controller, Post } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'

// const createAccountBodySchema = z.object({
//   name: z.string(),
//   email: z.string().email(),
//   password: z.string(),
// })

// type CreateAccountBodySchema = z.infer<typeof createAccountBodySchema>

@Controller('/sessions')
export class AuthenticateController {
  constructor(private jwt: JwtService) {}

  @Post()
  // @HttpCode(HttpStatus.OK)
  async handle() {
    const token = this.jwt.sign({ sub: 'user-id' })

    return {
      token,
    }

    // const { name, email, password } = createAccountBodySchema.parse(body)
    // const userWithSameEmail = await this.prisma.user.findUnique({
    //   where: {
    //     email,
    //   },
    // })
    // if (userWithSameEmail) {
    //   throw new ConflictException('User with same email already exists.')
    // }
    // const hashedPassword = await hash(password, 8)
    // await this.prisma.user.create({
    //   data: {
    //     name,
    //     email,
    //     password: hashedPassword,
    //   },
    // })
  }
}
